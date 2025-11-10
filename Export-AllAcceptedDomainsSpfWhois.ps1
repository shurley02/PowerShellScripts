<#
.SYNOPSIS
  Enumerate all Exchange Online accepted domains, get SPF → ip4/ip6 → WHOIS OrgName,
  and export a consolidated CSV.

.NOTES
  - Requires: Connect-ExchangeOnline (EXO V2 module) before running
  - Uses the user's baseline SPF/WHOIS logic (IncludedFrom + SpfPolicy + OrgName)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$CsvOutPath,

  [int]$WhoisTimeoutSeconds = 10,

  [string[]]$Domains,

  [string]$SkipRegex = '',

  [switch]$ShowChain
)

# -------------------- SPF / WHOIS functions --------------------
function Test-Command { param([string]$Name) [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue) }

function Get-SpfTxtRecords {
    param([string]$Domain)
    Write-Verbose ("Resolving TXT for {0}..." -f $Domain)
    $records = @()

    if (Test-Command 'Resolve-DnsName') {
        try {
            $txt = Resolve-DnsName -Name $Domain -Type TXT -ErrorAction Stop
            $records += $txt | ForEach-Object { ($_.Strings -join '') }
        } catch { Write-Verbose ("Resolve-DnsName failed for {0}: {1}" -f $Domain, $_.Exception.Message) }
    }

    if (-not $records -and (Test-Command 'dig')) {
        try {
            $out = & dig +short TXT $Domain 2>$null
            $records += ($out | ForEach-Object { $_ -replace '^\s*"', '' -replace '"\s*$', '' -replace '"\s*"', '' })
        } catch { Write-Verbose ("dig failed for {0}: {1}" -f $Domain, $_.Exception.Message) }
    }

    if (-not $records -and (Test-Command 'nslookup')) {
        try {
            $out = & nslookup -type=TXT $Domain 2>$null
            $lines = $out | Where-Object { $_ -match '"' }
            if ($lines) {
                $joined = ($lines -join ' ')
                $records += ($joined -split '"\s+"' -replace '"','') -join ''
            }
        } catch { Write-Verbose ("nslookup failed for {0}: {1}" -f $Domain, $_.Exception.Message) }
    }

    $spf = @($records | Where-Object { $_ -match '\bv=spf1\b' })
    return ,$spf
}

function Parse-SpfString {
    param([string]$SpfLine)
    $includes = [System.Collections.Generic.List[string]]::new()
    $ip4s     = [System.Collections.Generic.List[string]]::new()
    $ip6s     = [System.Collections.Generic.List[string]]::new()
    $policy   = 'none'

    $tokens = $SpfLine -split '\s+'
    foreach ($t in $tokens) {
        if     ($t -match '^include:(?<d>.+)$')  { $includes.Add($Matches.d.Trim()) }
        elseif ($t -match '^redirect=(?<d>.+)$') { $includes.Add($Matches.d.Trim()) }
        elseif ($t -match '^ip4:(?<a>.+)$')      { $ip4s.Add($Matches.a.Trim()) }
        elseif ($t -match '^ip6:(?<a>.+)$')      { $ip6s.Add($Matches.a.Trim()) }
        elseif ($t -match '^(?<q>[+\-~\?]?)(all)$') {
            switch ($Matches.q) {
                '-' { $policy = 'hardfail' }
                '~' { $policy = 'softfail' }
                '?' { $policy = 'neutral' }
                default { $policy = 'pass' }
            }
        }
    }

    [PSCustomObject]@{
        Includes = $includes
        IP4      = $ip4s
        IP6      = $ip6s
        Policy   = $policy
    }
}

function Normalize-Cidr {
    param([string]$Addr)
    if ($Addr -match ':') { if ($Addr -notmatch '/') { "$Addr/128" } else { $Addr } }
    else                  { if ($Addr -notmatch '/') { "$Addr/32" }  else { $Addr } }
}

$Global:WhoisOrder = @('whois.arin.net','whois.ripe.net','whois.apnic.net','whois.lacnic.net','whois.afrinic.net')
if (-not (Get-Variable -Name WhoisCache -Scope Script -ErrorAction SilentlyContinue)) { $script:WhoisCache = @{} }

function Invoke-WhoisRaw {
    param([string]$Server, [string]$QueryIp, [int]$TimeoutSeconds = 10)
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $async  = $client.BeginConnect($Server, 43, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) { $client.Close(); return $null }
        $client.EndConnect($async)
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII, $false, 1024, $true)
        $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::ASCII, 1024, $true)
        $writer.NewLine = "`r`n"; $writer.AutoFlush = $true
        $writer.WriteLine($QueryIp)
        $sb = [System.Text.StringBuilder]::new()
        $buffer = New-Object char[] 2048
        while ($true) {
            $read = $reader.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $null = $sb.Append($buffer, 0, $read)
        }
        $reader.Dispose(); $writer.Dispose(); $stream.Dispose(); $client.Close()
        ($sb.ToString() -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    } catch { return $null }
}

$IgnorePatterns = @('IPv4 address block not managed by the RIPE NCC','IPv6 address block not managed by the RIPE NCC')

function Parse-WhoisOrgName {
    param([string]$Text)
    if (-not $Text) { return $null }
    $lines = $Text -split "`r?`n"
    function IsIgnored([string]$s) { foreach ($pat in $IgnorePatterns) { if ($s -match [regex]::Escape($pat)) { return $true } } return $false }

    $patterns = @('^\s*OrgName\s*:\s*(.+)$','^\s*Organization\s*:\s*(.+)$','^\s*organisation\s*:\s*(.+)$','^\s*org-name\s*:\s*(.+)$','^\s*owner\s*:\s*(.+)$')

    foreach ($pat in $patterns) {
        foreach ($ln in $lines) {
            $m = [regex]::Match($ln, $pat, 'IgnoreCase')
            if ($m.Success) { $val = $m.Groups[1].Value.Trim(); if ($val -and -not (IsIgnored $val)) { return $val } }
        }
    }
    foreach ($ln in $lines) {
        $m = [regex]::Match($ln, '^\s*descr\s*:\s*(.+)$', 'IgnoreCase')
        if ($m.Success) { $val = $m.Groups[1].Value.Trim(); if ($val -and -not (IsIgnored $val)) { return $val } }
    }
    return $null
}

function Get-WhoisOrgName {
    param([string]$IpOrCidr, [int]$Timeout = 10)

    if ($script:WhoisCache.ContainsKey($IpOrCidr)) { return $script:WhoisCache[$IpOrCidr] }

    $ip = ($IpOrCidr -split '/')[0]

    # Try ARIN first
    $rawArinFirst = Invoke-WhoisRaw -Server 'whois.arin.net' -QueryIp $ip -TimeoutSeconds $Timeout
    if ($rawArinFirst) {
        $ref0 = [regex]::Match($rawArinFirst, 'ReferralServer:\s*whois://([^\s]+)', 'IgnoreCase')
        if ($ref0.Success) {
            $rawRef0 = Invoke-WhoisRaw -Server $ref0.Groups[1].Value.Trim() -QueryIp $ip -TimeoutSeconds $Timeout
            if ($rawRef0) { $rawArinFirst = $rawRef0 }
        }
        $org0 = Parse-WhoisOrgName -Text $rawArinFirst
        if ($org0) {
            $obj0 = [PSCustomObject]@{ OrgName=$org0; Registry='whois.arin.net'; Raw=$rawArinFirst }
            $script:WhoisCache[$IpOrCidr] = $obj0
            return $obj0
        }
    }

    foreach ($server in $Global:WhoisOrder) {
        $raw = Invoke-WhoisRaw -Server $server -QueryIp $ip -TimeoutSeconds $Timeout
        if (-not $raw) { continue }
        $ref = [regex]::Match($raw, 'ReferralServer:\s*whois://([^\s]+)', 'IgnoreCase')
        if ($ref.Success) {
            $rawRef = Invoke-WhoisRaw -Server $ref.Groups[1].Value.Trim() -QueryIp $ip -TimeoutSeconds $Timeout
            if ($rawRef) { $raw = $rawRef }
        }
        $org = Parse-WhoisOrgName -Text $raw
        if ((-not $org) -and ($server -like '*ripe*') -and ($raw -match 'not managed by the RIPE NCC')) {
            $rawArin = Invoke-WhoisRaw -Server 'whois.arin.net' -QueryIp $ip -TimeoutSeconds $Timeout
            if ($rawArin) { $org = Parse-WhoisOrgName -Text $rawArin; $raw = $rawArin }
        }
        if ($org) {
            $obj = [PSCustomObject]@{ OrgName=$org; Registry=$server; Raw=$raw }
            $script:WhoisCache[$IpOrCidr] = $obj
            return $obj
        }
    }
    $objNull = [PSCustomObject]@{ OrgName=$null; Registry=$null; Raw=$null }
    $script:WhoisCache[$IpOrCidr] = $objNull
    return $objNull
}

# -------------------- SPF processing per domain --------------------
function Get-SpfWhoisForDomain {
    param([string]$Domain, [switch]$ShowChain, [int]$WhoisTimeoutSeconds = 10)

    $VisitedDomains      = [System.Collections.Generic.HashSet[string]]::new()
    $CollectedCidrs      = [System.Collections.Generic.HashSet[string]]::new()
    $IncludesEncountered = [System.Collections.Generic.HashSet[string]]::new()
    $BlockSources        = @{}
    $DomainPolicies      = @{}

    function Add-BlockSource {
        param([string]$Cidr, [string]$SourceString)
        if (-not $BlockSources.ContainsKey($Cidr)) {
            $BlockSources[$Cidr] = [System.Collections.Generic.HashSet[string]]::new()
        }
        $BlockSources[$Cidr].Add($SourceString) | Out-Null
    }

    function Resolve-SpfRecursive {
        param([string]$CurrentDomain, [string[]]$Path)
        if ($VisitedDomains.Contains($CurrentDomain)) { return }
        $VisitedDomains.Add($CurrentDomain) | Out-Null
        $spfRecords = Get-SpfTxtRecords -Domain $CurrentDomain
        if (-not $spfRecords -or $spfRecords.Count -eq 0) { return }
        foreach ($raw in $spfRecords) {
            $spf = $raw.Trim(' "')
            $parsed = Parse-SpfString -SpfLine $spf
            if (-not $DomainPolicies.ContainsKey($CurrentDomain)) {
                $DomainPolicies[$CurrentDomain] = $parsed.Policy
            }
            foreach ($i in $parsed.IP4) {
                $n = Normalize-Cidr $i
                $CollectedCidrs.Add($n) | Out-Null
                $src = if ($ShowChain) { ($Path + $CurrentDomain) -join ' -> ' } else { $CurrentDomain }
                Add-BlockSource -Cidr $n -SourceString $src
            }
            foreach ($i6 in $parsed.IP6) {
                $n6 = Normalize-Cidr $i6
                $CollectedCidrs.Add($n6) | Out-Null
                $src = if ($ShowChain) { ($Path + $CurrentDomain) -join ' -> ' } else { $CurrentDomain }
                Add-BlockSource -Cidr $n6 -SourceString $src
            }
            foreach ($inc in $parsed.Includes) {
                $IncludesEncountered.Add($inc) | Out-Null
                Resolve-SpfRecursive -CurrentDomain $inc -Path ($Path + $CurrentDomain)
            }
        }
    }

    Resolve-SpfRecursive -CurrentDomain $Domain -Path @()

    $output = @()
    if ($CollectedCidrs.Count -eq 0) {
        $output += [PSCustomObject]@{
            Domain       = $Domain
            Block        = '<none>'
            IncludedFrom = ''
            SpfPolicy    = if ($DomainPolicies.ContainsKey($Domain)) { $DomainPolicies[$Domain] } else { 'none' }
            OrgName      = ''
            Source       = ''
        }
        return $output
    }

    foreach ($cidr in $CollectedCidrs) {
        $includedFromSet = if ($BlockSources.ContainsKey($cidr)) { $BlockSources[$cidr] } else { $null }
        $includedFrom = if ($includedFromSet) { ($includedFromSet | Sort-Object) -join ', ' } else { '' }

        $policies = @()
        if ($includedFromSet) {
            foreach ($src in $includedFromSet) {
                $srcDomain = if ($ShowChain -and ($src -match '->')) { ($src -split '->')[-1].Trim() } else { $src }
                if ($DomainPolicies.ContainsKey($srcDomain)) {
                    $policies += $DomainPolicies[$srcDomain]
                }
            }
        }
        $policies = ($policies | Where-Object { $_ } | Select-Object -Unique) -join ', '
        if (-not $policies) { $policies = 'none' }

        $whois = Get-WhoisOrgName -IpOrCidr $cidr -Timeout $WhoisTimeoutSeconds
        $output += [PSCustomObject]@{
            Domain       = $Domain
            Block        = $cidr
            IncludedFrom = $includedFrom
            SpfPolicy    = $policies
            OrgName      = $whois.OrgName
            Source       = if ($whois.Registry) { "WHOIS:$($whois.Registry)" } else { "WHOIS" }
        }
    }
    return $output
}

# -------------------- Main: iterate domains --------------------
if (-not $Domains -or $Domains.Count -eq 0) {
    try {
        $Domains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
    } catch {
        Write-Error "Failed to enumerate accepted domains. Connect-ExchangeOnline first. $_"
        break
    }
}

if ($SkipRegex) { $Domains = $Domains | Where-Object { $_ -notmatch $SkipRegex } }
$Domains = $Domains | Sort-Object -Unique
Write-Host ("Processing {0} accepted domain(s)..." -f $Domains.Count) -ForegroundColor Cyan

$allRows = @()
$idx = 0
foreach ($d in $Domains) {
    $idx++
    Write-Host ("[{0}/{1}] {2}" -f $idx, $Domains.Count, $d) -ForegroundColor Gray
    $rows = Get-SpfWhoisForDomain -Domain $d -ShowChain:$ShowChain.IsPresent -WhoisTimeoutSeconds $WhoisTimeoutSeconds
    if ($rows) { $allRows += $rows }
}

if (-not $allRows -or $allRows.Count -eq 0) {
    Write-Warning "No data collected. Nothing to export."
    return
}

$allRows = $allRows | Sort-Object Domain, IncludedFrom, OrgName, Block
try {
    $allRows | Export-Csv -Path $CsvOutPath -NoTypeInformation -Encoding UTF8
    Write-Host ("CSV written to {0}" -f $CsvOutPath) -ForegroundColor Green
} catch {
    Write-Error "Failed to write CSV: $_"
}
