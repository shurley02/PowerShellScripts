<#
.SYNOPSIS
Remove all SMTP/smtp proxyAddresses on @domaina.com after primary was moved
to @domainb.com (or another domain).

Defaults: Remote Mailboxes only. Skips objects whose primary is still @domaina.com.

Switches let you include on-prem Mailboxes, Distribution Groups, Dynamic DLs,
MailUsers, MailContacts, and MailPublicFolders.

Use -ConfirmEach to interactively review each change; -WhatIf to preview.
#>

[CmdletBinding()]
param(
  [string]$OldDomain = 'domaina.com',
  [switch]$IncludeOnPremMailboxes,
  [switch]$IncludeGroups,
  [switch]$IncludeDynamicGroups,
  [switch]$IncludeContacts,          # MailUsers + MailContacts
  [switch]$IncludePublicFolders,
  [switch]$ConfirmEach,
  [switch]$WhatIf
)

# ---------- Helpers ----------
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

# Remove smtp entries with old domain; keep everything else
function Build-CleanedProxies {
  param(
    [string[]]$Current,
    [string]$OldDomain
  )
  $pattern = '^(?i)smtp:[^@]+@' + [regex]::Escape($OldDomain) + '$'
  $Current |
    ForEach-Object { $_.ToString().Trim() } |
    Where-Object { $_ -and ($_ -notmatch $pattern) } |
    Select-Object -Unique
}

function Scrub-Recipient {
  param(
    [Parameter(Mandatory=$true)] $Recipient,
    [Parameter(Mandatory=$true)] [string]$OldDomain,
    [Parameter(Mandatory=$true)] [ValidateSet('RemoteMailbox','Mailbox','DG','DDG','MailUser','MailContact','MailPublicFolder')] [string]$Type,
    [Parameter(Mandatory=$true)] [bool]$ConfirmEachMode,
    [Parameter(Mandatory=$true)] [bool]$WhatIfMode
  )

  $idStr   = Resolve-IdentityString -R $Recipient
  $primary = ($Recipient.PrimarySmtpAddress -as [string])

  # Skip if primary still on old domain
  if ($primary -and ($primary -match "@$([regex]::Escape($OldDomain))$")) {
    Write-Warning "Skipping $($Recipient.DisplayName) (primary still $primary)"
    return
  }

  # Only act if any old-domain address is present
  $curr = @($Recipient.EmailAddresses | ForEach-Object { $_.ToString() })
  $hasOld = $curr | Where-Object { $_ -match "@$([regex]::Escape($OldDomain))$" -and $_ -match '^(?i)smtp:' }
  if (-not $hasOld) { return }

  $clean = Build-CleanedProxies -Current $curr -OldDomain $OldDomain

  # If nothing changed (defensive), return
  if (@($curr).Count -eq @($clean).Count) { return }

  if ($ConfirmEachMode) {
    Write-Host "------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ("Type      : {0}" -f $Type)
    Write-Host ("Recipient : {0}" -f $Recipient.DisplayName)
    Write-Host ("Primary   : {0}" -f $primary)
    Write-Host "Current proxyAddresses:" -ForegroundColor Yellow
    foreach ($p in $curr) { Write-Host ("  {0}" -f $p) }
    Write-Host "Proposed proxyAddresses (old domain removed):" -ForegroundColor Green
    foreach ($p in $clean) { Write-Host ("  {0}" -f $p) }
    $resp = Read-Host "Press Enter to APPLY, 'S' to skip, or 'Q' to quit"
    if ($resp -match '^(?i)q(uit)?$') { throw "Aborted by operator." }
    if ($resp -match '^(?i)s(kip)?$') { Write-Host "Skipped." -ForegroundColor DarkYellow; return }
  } else {
    Write-Host ("Scrubbing {0} ({1})" -f $Recipient.DisplayName, $Type) -ForegroundColor Cyan
  }

  $common = @{
    Identity       = $idStr
    EmailAddresses = $clean
  }
  if ($WhatIfMode) { $common['WhatIf'] = $true }

  switch ($Type) {
    'RemoteMailbox'   { Set-RemoteMailbox @common }
    'Mailbox'         { Set-Mailbox @common }
    'DG'              { Set-DistributionGroup @common }
    'DDG'             { try { Set-DynamicDistributionGroup @common } catch { Write-Warning "Set-DDG failed: $_" } }
    'MailUser'        { Set-MailUser @common }
    'MailContact'     { Set-MailContact @common }
    'MailPublicFolder'{ Set-MailPublicFolder @common }
  }
}

# ---------- Remote Mailboxes (default) ----------
Get-RemoteMailbox -ResultSize Unlimited -Filter "EmailAddresses -like '*@$OldDomain'" |
  ForEach-Object {
    Scrub-Recipient -Recipient $_ -OldDomain $OldDomain -Type 'RemoteMailbox' -ConfirmEachMode:$ConfirmEach.IsPresent -WhatIfMode:$WhatIf.IsPresent
  }

# ---------- (Optional) On-Prem Mailboxes ----------
if ($IncludeOnPremMailboxes) {
  Get-Mailbox -ResultSize Unlimited -Filter "EmailAddresses -like '*@$OldDomain'" |
    ForEach-Object {
      Scrub-Recipient -Recipient $_ -OldDomain $OldDomain -Type 'Mailbox' -ConfirmEachMode:$ConfirmEach.IsPresent -WhatIfMode:$WhatIf.IsPresent
    }
}

# ---------- (Optional) Groups ----------
if ($IncludeGroups) {
  Get-DistributionGroup -ResultSize Unlimited -Filter "EmailAddresses -like '*@$OldDomain'" |
    ForEach-Object {
      Scrub-Recipient -Recipient $_ -OldDomain $OldDomain -Type 'DG' -ConfirmEachMode:$ConfirmEach.IsPresent -WhatIfMode:$WhatIf.IsPresent
    }
}
if ($IncludeDynamicGroups) {
  Get-DynamicDistributionGroup -ResultSize Unlimited -Filter "EmailAddresses -like '*@$OldDomain'" |
    ForEach-Object {
      Scrub-Recipient -Recipient $_ -OldDomain $OldDomain -Type 'DDG' -ConfirmEachMode:$ConfirmEach.IsPresent -WhatIfMode:$WhatIf.IsPresent
    }
}

# ---------- (Optional) Mail Users / Contacts ----------
if ($IncludeContacts) {
  Get-MailUser -ResultSize Unlimited -Filter "EmailAddresses -like '*@$OldDomain'" |
    ForEach-Object {
      Scrub-Recipient -Recipient $_ -OldDomain $OldDomain -Type 'MailUser' -ConfirmEachMode:$ConfirmEach.IsPresent -WhatIfMode:$WhatIf.IsPresent
    }
  Get-MailContact -ResultSize Unlimited -Filter "EmailAddresses -like '*@$OldDomain'" |
    ForEach-Object {
      Scrub-Recipient -Recipient $_ -OldDomain $OldDomain -Type 'MailContact' -ConfirmEachMode:$ConfirmEach.IsPresent -WhatIfMode:$WhatIf.IsPresent
    }
}

# ---------- (Optional) Mail-enabled Public Folders ----------
if ($IncludePublicFolders) {
  Get-MailPublicFolder -ResultSize Unlimited -Filter "EmailAddresses -like '*@$OldDomain'" |
    ForEach-Object {
      Scrub-Recipient -Recipient $_ -OldDomain $OldDomain -Type 'MailPublicFolder' -ConfirmEachMode:$ConfirmEach.IsPresent -WhatIfMode:$WhatIf.IsPresent
    }
}
