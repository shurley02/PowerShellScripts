<#
.SYNOPSIS
Flip primary SMTP from @domaina.com to @domainb.com ONLY where the current
PrimarySmtpAddress ends with @domaina.com.

- Works for Remote Mailboxes (EXO) and, optionally, on-prem Mailboxes.
- Keeps same local-part. Old primary is demoted to alias; all other proxies preserved.
- Toggle per-user confirmation with -ConfirmEach (on = interactive, off = auto).
- Uses EmailAddresses ONLY (uppercase SMTP: entry becomes primary).
#>

[CmdletBinding()]
param(
  [string]$OldDomain = 'domaina.com',
  [string]$NewDomain = 'domainb.com',
  [switch]$IncludeOnPremMailboxes,   # also process on-prem mailboxes
  [switch]$WhatIf,                   # preview changes
  [switch]$ConfirmEach               # show pause/confirm per user
)

# Optional sanity check: ensure new domain exists as Accepted Domain on-prem
try {
  if (-not (Get-AcceptedDomain -ErrorAction SilentlyContinue | Where-Object { $_.DomainName -ieq $NewDomain })) {
    Write-Warning "Accepted Domain '$NewDomain' not found on-prem. Add it before proceeding."
  }
} catch {
  # Ignore if Get-AcceptedDomain isn't available in this session
}

# Resolve a simple string Identity for Set-RemoteMailbox / Set-Mailbox
function Resolve-IdentityString {
  param([Parameter(Mandatory=$true)]$R)
  @(
    ($R.PrimarySmtpAddress -as [string]),
    ($R.Alias -as [string]),
    ($R.Guid -as [string]),
    ($R.UserPrincipalName -as [string]),
    ($R.DistinguishedName -as [string])  # last resort
  ) | Where-Object { $_ } | Select-Object -First 1
}

function Flip-PrimaryForRecipient {
  param(
    [Parameter(Mandatory=$true)] $Recipient,      # RemoteMailbox or Mailbox object
    [Parameter(Mandatory=$true)] [string]$OldDomain,
    [Parameter(Mandatory=$true)] [string]$NewDomain,
    [Parameter(Mandatory=$true)] [bool]$IsRemote, # $true for RemoteMailbox
    [Parameter(Mandatory=$true)] [bool]$WhatIfMode,
    [Parameter(Mandatory=$true)] [bool]$ConfirmEachMode
  )

  $oldPrimary = $Recipient.PrimarySmtpAddress.ToString()
  if ($oldPrimary -notmatch "@$([regex]::Escape($OldDomain))$") { return }  # not a target

  $localPart  = $oldPrimary.Split('@')[0]
  $newPrimary = "$localPart@$NewDomain"

  # Current proxies as strings
  $currentProxies = @($Recipient.EmailAddresses | ForEach-Object { $_.ToString() })

  # Build proposed list:
  # - demote all SMTP entries to lowercase aliases
  # - skip adding newPrimary as alias (will be uppercase PRIMARY)
  $aliases =
    $currentProxies |
    ForEach-Object {
      if ($_ -match '^(?i)smtp:') {
        $val = $_.Substring(5)
        if ($val -ieq $newPrimary) { $null } else { "smtp:$val".ToLower() }
      } else {
        $_
      }
    } |
    Where-Object { $_ } |
    Select-Object -Unique

  # Ensure old primary is preserved as alias
  $oldAlias = ("smtp:{0}" -f $oldPrimary).ToLower()
  if ($aliases -notcontains $oldAlias) { $aliases += $oldAlias }

  # Final list: PRIMARY first (uppercase) then aliases
  $final = @("SMTP:$newPrimary") + ($aliases | Select-Object -Unique)

  # --------------- Interactive or Auto ---------------
  if ($ConfirmEachMode) {
    Write-Host "------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ("Recipient : {0}" -f $Recipient.DisplayName)
    Write-Host ("Alias     : {0}" -f $Recipient.Alias)
    Write-Host ("Primary   : {0}  -->  {1}" -f $oldPrimary, $newPrimary) -ForegroundColor Cyan

    Write-Host "Current proxyAddresses:" -ForegroundColor Yellow
    foreach ($p in $currentProxies) { Write-Host ("  {0}" -f $p) }

    Write-Host "Proposed proxyAddresses:" -ForegroundColor Green
    foreach ($p in $final) { Write-Host ("  {0}" -f $p) }

    $resp = Read-Host "Press Enter to APPLY, 'S' to skip, or 'Q' to quit"
    if ($resp -match '^(?i)q(uit)?$') { throw "Aborted by operator." }
    if ($resp -match '^(?i)s(kip)?$') { Write-Host "Skipped." -ForegroundColor DarkYellow; return }
  } else {
    Write-Host ("{0}  -->  {1}  ({2})" -f $oldPrimary, $newPrimary, $Recipient.Alias) -ForegroundColor Cyan
  }

  # --------------- Apply (EmailAddresses ONLY) ---------------
  $id = Resolve-IdentityString -R $Recipient

  $params = @{
    Identity                  = $id
    EmailAddressPolicyEnabled = $false   # prevent policy from flipping back
    EmailAddresses            = $final   # PRIMARY determined by uppercase SMTP:
  }
  if ($WhatIfMode) { $params['WhatIf'] = $true }

  if ($IsRemote) {
    Set-RemoteMailbox @params
  } else {
    Set-Mailbox @params
  }
} # end function

# --------- Remote Mailboxes (typical in hybrid) ---------
Get-RemoteMailbox -ResultSize Unlimited |
  Where-Object { $_.PrimarySmtpAddress -match "@$([regex]::Escape($OldDomain))$" } |
  ForEach-Object {
    Flip-PrimaryForRecipient `
      -Recipient $_ `
      -OldDomain $OldDomain `
      -NewDomain $NewDomain `
      -IsRemote:$true `
      -WhatIfMode:$WhatIf.IsPresent `
      -ConfirmEachMode:$ConfirmEach.IsPresent
  }

# --------- (Optional) On-prem Mailboxes ----------
if ($IncludeOnPremMailboxes) {
  Get-Mailbox -ResultSize Unlimited |
    Where-Object { $_.PrimarySmtpAddress -match "@$([regex]::Escape($OldDomain))$" } |
    ForEach-Object {
      Flip-PrimaryForRecipient `
        -Recipient $_ `
        -OldDomain $OldDomain `
        -NewDomain $NewDomain `
        -IsRemote:$false `
        -WhatIfMode:$WhatIf.IsPresent `
        -ConfirmEachMode:$ConfirmEach.IsPresent
    }
}
