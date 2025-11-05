<#
.SYNOPSIS
  Resolve a domain’s SPF, recursively follow includes/redirect, enumerate ip4/ip6 CIDRs,
  and return the WHOIS OrgName (e.g., Disney Worldwide Services, Inc.; Microsoft Corporation; Proofpoint, Inc.).
  Adds IncludedFrom column to show which SPF record contained the IP/block.

.NOTES
  - Cross-platform (PowerShell 7+ recommended)
  - Requires outbound TCP/43 (WHOIS)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Domain,

    [int]$WhoisTimeoutSeconds = 10,

    [string]$CsvOutPath,

    [switch]$GroupByOwner,

    # If set, IncludedFrom shows the full include chain "root → include1 → include2".
    # Otherwise it shows just the SPF domain that directly listed the ip4/ip6.
    [switch]$ShowChain
)

# -------------------- Utilities --------------------
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

    $tokens = $SpfLine -split '\s+'
    foreach ($t in $tokens) {
        if     ($t -match '^include:(?<d>.+)$')  { $includes.Add($Matches.d.Trim()) }
        elseif ($t -match '^redirect=(?<d>.+)$') { $includes.Add($Matches.d.Trim()) }
        elseif ($t -match '^ip4:(?<a>.+)$')      { $ip4s.Add($Matches.a.Trim()) }
        elseif ($t -match '^ip6:(?<a>.+)$')      { $ip6s.Add($Matches.a.Trim()) }
    }

    [PSCustomObject]@{ Includes = $includes; IP4 = $ip4s; IP6 = $ip6s }
}

function Normalize-Cidr {
    param([string]$Addr)
    if ($Addr -match ':') { if ($Addr -notmatch '/') { "$Addr/128" } else { $Addr } }
    else                  { if ($Addr -notmatch '/') { "$Addr/32" }  else { $Addr } }
}

# -------------------- WHOIS --------------------
$Global:WhoisOrder = @('whois.arin.net','whois.ripe.net','whois.apnic.net','whois.lacnic.net','whois.afrinic.net')
$WhoisCache = @{}

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
        # IMPORTANT: Send just the IP (no CIDR)
        $writer.WriteLine($QueryIp)

        $sb = [System.Text.StringBuilder]::new()
        $buffer = New-Object char[] 2048
        while ($true) {
            $read = $reader.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $null = $sb.Append($buffer, 0, $read)
        }
        $reader.Dispose(); $writer.Dispose(); $stream.Dispose(); $client.Close()
        # Remove ARIN banner (# lines) to reduce noise
        $txt = ($sb.ToString() -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        return $txt
    } catch { return $null }
}

# Prefer real organization fields; explicitly ignore RIPE’s “not managed by the RIPE NCC”
$IgnorePatterns = @(
    'IPv4 address block not managed by the RIPE NCC'
)

function Parse-WhoisOrgName {
    param([string]$Text)
    if (-not $Text) { return $null }
    $lines = $Text -split "`r?`n"

    # If any line matches an ignore pattern, we do NOT use it
    function IsIgnored([string]$s) {
        foreach ($pat in $IgnorePatterns) { if ($s -match [regex]::Escape($pat)) { return $true } }
        return $false
    }

    # Strict org-first patterns
    $patterns = @(
        '^\s*OrgName\s*:\s*(.+)$',       # ARIN (OrgName)
        '^\s*Organization\s*:\s*(.+)$',  # ARIN sometimes uses this too
        '^\s*organisation\s*:\s*(.+)$',  # RIPE
        '^\s*org-name\s*:\s*(.+)$',      # RIPE
        '^\s*owner\s*:\s*(.+)$'          # LACNIC
        # (No 'descr' here to avoid banners; we’ll only use it as a last resort and filter it)
    )

    foreach ($pat in $patterns) {
        foreach ($ln in $lines) {
            $m = [regex]::Match($ln, $pat, 'IgnoreCase')
            if ($m.Success) {
                $val = $m.Groups[1].Value.Trim()
                if ($val -and -not (IsIgnored $val)) { return $val }
            }
        }
    }

    # Last-resort: try 'descr:', but filter out RIPE banner text
    foreach ($ln in $lines) {
        $m = [regex]::Match($ln, '^\s*descr\s*:\s*(.+)$', 'IgnoreCase')
        if ($m.Success) {
            $val = $m.Groups[1].Value.Trim()
            if ($val -and -not (IsIgnored $val)) { return $val }
        }
    }

    return $null
}

function Get-WhoisOrgName {
    param([string]$IpOrCidr, [int]$Timeout = 10)

    if ($WhoisCache.ContainsKey($IpOrCidr)) { return $WhoisCache[$IpOrCidr] }

    # Use just the IP for the whois query
    $ip = ($IpOrCidr -split '/')[0]

    foreach ($server in $Global:WhoisOrder) {
        Write-Verbose ("WHOIS {0} -> {1}" -f $server, $ip)
        $raw = Invoke-WhoisRaw -Server $server -QueryIp $ip -TimeoutSeconds $Timeout
        if (-not $raw) { continue }

        # ARIN referral follow
        $ref = [regex]::Match($raw, 'ReferralServer:\s*whois://([^\s]+)', 'IgnoreCase')
        if ($ref.Success) {
            $refServer = $ref.Groups[1].Value.Trim()
            Write-Verbose ("Following referral to {0}" -f $refServer)
            $rawRef = Invoke-WhoisRaw -Server $refServer -QueryIp $ip -TimeoutSeconds $Timeout
            if ($rawRef) { $raw = $rawRef }
        }

        $org = Parse-WhoisOrgName -Text $raw

        # Special case: RIPE “not managed by the RIPE NCC” → try ARIN directly
        if ((-not $org) -and ($server -like '*ripe*') -and ($raw -match 'not managed by the RIPE NCC')) {
            Write-Verbose "RIPE mirror notice seen; retrying whois.arin.net"
            $rawArin = Invoke-WhoisRaw -Server 'whois.arin.net' -QueryIp $ip -TimeoutSeconds $Timeout
            if ($rawArin) { $org = Parse-WhoisOrgName -Text $rawArin; $raw = $rawArin }
        }

        if ($org) {
            $obj = [PSCustomObject]@{ OrgName=$org; Registry=$server; Raw=$raw }
            $WhoisCache[$IpOrCidr] = $obj
            return $obj
        }
    }

    $objNull = [PSCustomObject]@{ OrgName=$null; Registry=$null; Raw=$null }
    $WhoisCache[$IpOrCidr] = $objNull
    return $objNull
}

# -------------------- SPF recursion + provenance --------------------
$VisitedDomains      = [System.Collections.Generic.HashSet[string]]::new()
$CollectedCidrs      = [System.Collections.Generic.HashSet[string]]::new()
$IncludesEncountered = [System.Collections.Generic.HashSet[string]]::new()
$BlockSources        = @{}   # CIDR -> HashSet of source strings

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

        foreach ($i in $parsed.IP4) {
            $n = Normalize-Cidr $i
            $CollectedCidrs.Add($n) | Out-Null
            $src = if ($ShowChain) { ($Path + $CurrentDomain) -join ' → ' } else { $CurrentDomain }
            Add-BlockSource -Cidr $n -SourceString $src
        }
        foreach ($i6 in $parsed.IP6) {
            $n6 = Normalize-Cidr $i6
            $CollectedCidrs.Add($n6) | Out-Null
            $src = if ($ShowChain) { ($Path + $CurrentDomain) -join ' → ' } else { $CurrentDomain }
            Add-BlockSource -Cidr $n6 -SourceString $src
        }
        foreach ($inc in $parsed.Includes) {
            $IncludesEncountered.Add($inc) | Out-Null
            Resolve-SpfRecursive -CurrentDomain $inc -Path ($Path + $CurrentDomain)
        }
    }
}

# -------------------- Run --------------------
Resolve-SpfRecursive -CurrentDomain $Domain -Path @()

if ($CollectedCidrs.Count -eq 0) {
    Write-Host ("No ip4/ip6 entries found in SPF for {0}." -f $Domain) -ForegroundColor Yellow
    return
}

Write-Host ("Found {0} IP block(s). Looking up OrgNames via WHOIS..." -f $CollectedCidrs.Count) -ForegroundColor Cyan

$results = foreach ($cidr in $CollectedCidrs) {
    $includedFrom = if ($BlockSources.ContainsKey($cidr)) {
        ($BlockSources[$cidr] | Sort-Object) -join ', '
    } else { '' }

    $whois = Get-WhoisOrgName -IpOrCidr $cidr -Timeout $WhoisTimeoutSeconds
    [PSCustomObject]@{
        Block        = $cidr
        IncludedFrom = $includedFrom
        OrgName      = $whois.OrgName
        Source       = if ($whois.Registry) { "WHOIS:$($whois.Registry)" } else { "WHOIS" }
    }
}

$results = $results | Sort-Object OrgName, Block

if ($GroupByOwner) {
    $groups = $results | Group-Object OrgName
    foreach ($g in $groups) {
        $name = if ($g.Name) { $g.Name } else { "(unknown)" }
        Write-Host "`n== $name ==" -ForegroundColor Cyan
        ($g.Group | Select-Object Block, IncludedFrom, Source | Sort-Object Block) | Format-Table -AutoSize
    }
} else {
    $results | Select-Object Block, IncludedFrom, OrgName, Source | Format-Table -AutoSize
}

if ($CsvOutPath) {
    try {
        $results | Export-Csv -Path $CsvOutPath -NoTypeInformation -Encoding UTF8
        Write-Host ("Exported CSV -> {0}" -f $CsvOutPath) -ForegroundColor Green
    } catch {
        Write-Warning ("Failed to write CSV: {0}" -f $_.Exception.Message)
    }
}

if ($IncludesEncountered.Count -gt 0) {
    Write-Host "`nIncludes followed:" -ForegroundColor Cyan
    $IncludesEncountered | Sort-Object | ForEach-Object { Write-Host (" - {0}" -f $_) }
}
