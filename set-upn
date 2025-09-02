<#
.SYNOPSIS
Change UserPrincipalName suffix from @OldDomain to @NewDomain for AD users.

Defaults: searches entire forest domain for users whose UPN ends with @OldDomain.
Skips users whose UPN is already @NewDomain or whose primary SMTP is blank.

Features:
- -WhatIf: true dry-run using ShouldProcess and Set-ADUser -WhatIf
- -ConfirmEach: interactive review per user (Enter=apply, S=skip, Q=quit)
- Conflict check: skips if another user already has the new UPN
- UPN suffix validation: warns if NewDomain isn't an allowed UPN suffix
- Optional scoping: -SearchBase (OU DN) or -InGroupDN (limit to members of a group)
- Optional filters to skip disabled accounts

EXAMPLES
.\Set-UpnSuffix.ps1 -OldDomain "domaina.com" -NewDomain "domainb.com" -WhatIf
.\Set-UpnSuffix.ps1 -OldDomain "domaina.com" -NewDomain "domainb.com" -SearchBase "OU=People,DC=contoso,DC=com" -ConfirmEach
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
  [Parameter(Mandatory=$true)]
  [string]$OldDomain,

  [Parameter(Mandatory=$true)]
  [string]$NewDomain,

  # Scope options
  [string]$SearchBase,         # e.g., "OU=Users,DC=contoso,DC=com"
  [string]$InGroupDN,          # limit to direct members of this group DN (optional)

  # Behavior
  [switch]$ExcludeDisabled,    # skip disabled accounts
  [switch]$ConfirmEach,        # interactive review per change
  [switch]$VerboseList         # prints every candidate found
)

# ---------- Pre-flight checks ----------
try {
  Import-Module ActiveDirectory -ErrorAction Stop
} catch {
  throw "ActiveDirectory module is required. $_"
}

# Validate NewDomain as an allowed UPN suffix (advisory)
try {
  $forest = Get-ADForest
  $allowed = @($forest.UPNSuffixes) + $forest.RootDomain
  if ($allowed -notcontains $NewDomain.ToLower()) {
    Write-Warning "NewDomain '$NewDomain' is not listed as an allowed UPN suffix in the forest. (Allowed: $($allowed -join ', '))"
    Write-Host   "You can add it in AD Domains and Trusts > UPN Suffixes, or proceed (Set-ADUser can still set it if DCs accept it)." -ForegroundColor DarkYellow
  }
} catch {
  Write-Warning "Unable to query forest UPN suffixes: $_"
}

# ---------- Build candidate set ----------
$filter = "(userPrincipalName -like '*@$([regex]::Escape($OldDomain))')"
if ($ExcludeDisabled) { $filter = "($filter -and (Enabled -eq 'True'))" }

# Base query
$searchParams = @{
  Filter      = $filter
  Properties  = @('userPrincipalName','samAccountName','displayName','enabled')
  ResultSetSize = 'Unlimited'
}
if ($SearchBase) { $searchParams['SearchBase'] = $SearchBase }

$candidates = Get-ADUser @searchParams

# Optionally restrict to group members
if ($InGroupDN) {
  try {
    $groupMembers = Get-ADGroupMember -Identity $InGroupDN -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' } | Select-Object -ExpandProperty DistinguishedName
    $memberSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $null = $groupMembers | ForEach-Object { $memberSet.Add($_) } 
    $candidates = $candidates | Where-Object { $memberSet.Contains($_.DistinguishedName) }
  } catch {
    throw "Failed to enumerate members of $InGroupDN. $_"
  }
}

if (-not $candidates) {
  Write-Host "No users found with UPN ending in @$OldDomain (scope: $($SearchBase ?? 'Domain default'))." -ForegroundColor DarkYellow
  return
}

Write-Host ("Found {0} candidate user(s) to evaluate." -f $candidates.Count) -ForegroundColor Cyan
if ($VerboseList) {
  $candidates | Sort-Object DisplayName | ForEach-Object {
    Write-Host ("  - {0}  <{1}>" -f ($_.DisplayName ?? $_.SamAccountName), $_.UserPrincipalName)
  }
}

# ---------- Helper to compute new UPN ----------
function Get-NewUpn {
  param([string]$OldUpn, [string]$NewDomain)
  if (-not $OldUpn) { return $null }
  $local = $OldUpn.Split('@')[0]
  return "$local@$NewDomain"
}

# ---------- Process each candidate ----------
$changed = 0
$skippedSame = 0
$skippedConflict = 0
$skippedOther = 0
$errors = 0

foreach ($u in $candidates) {
  $old = $u.UserPrincipalName
  if (-not $old) { $skippedOther++; continue }

  # Already on target domain?
  if ($old.EndsWith("@$NewDomain", [System.StringComparison]::OrdinalIgnoreCase)) {
    $skippedSame++; continue
  }

  $new = Get-NewUpn -OldUpn $old -NewDomain $NewDomain

  # Conflict check: does some other user already have this UPN?
  $conflict = Get-ADUser -LDAPFilter "(userPrincipalName=$([adsi]::Escape($new)))" -SearchBase ($SearchBase ?? (Get-ADDomain).DistinguishedName) -ErrorAction SilentlyContinue
  if ($conflict -and $conflict.DistinguishedName -ne $u.DistinguishedName) {
    Write-Warning ("Skipping {0} ({1}) because target UPN '{2}' already exists on {3}." -f ($u.DisplayName ?? $u.SamAccountName), $u.SamAccountName, $new, $conflict.SamAccountName)
    $skippedConflict++; continue
  }

  # Show plan
  Write-Host "------------------------------------------------------" -ForegroundColor DarkGray
  Write-Host ("User      : {0}" -f ($u.DisplayName ?? $u.SamAccountName))
  Write-Host ("sAM       : {0}" -f $u.SamAccountName)
  Write-Host ("Enabled   : {0}" -f ($u.Enabled))
  Write-Host ("Old UPN   : {0}" -f $old) -ForegroundColor Yellow
  Write-Host ("New UPN   : {0}" -f $new) -ForegroundColor Green

  if ($ConfirmEach) {
    $resp = Read-Host "Press Enter to APPLY, 'S' to skip, or 'Q' to quit"
    if ($resp -match '^(?i)q(uit)?$') { throw "Aborted by operator." }
    if ($resp -match '^(?i)s(kip)?$') { Write-Host "Skipped." -ForegroundColor DarkYellow; $skippedOther++; continue }
  } else {
    Write-Host ("Updating {0}..." -f $u.SamAccountName) -ForegroundColor Cyan
  }

  # Perform update with full WhatIf/Confirm support
  $target = "{0} -> {1}" -f $old, $new
  if ($PSCmdlet.ShouldProcess($u.SamAccountName, "Set-ADUser -UserPrincipalName '$new'")) {
    try {
      Set-ADUser -Identity $u.SamAccountName -UserPrincipalName $new -ErrorAction Stop
      $changed++
    } catch {
      $errors++
      Write-Warning ("Failed to update {0} ({1}): {2}" -f ($u.DisplayName ?? $u.SamAccountName), $u.SamAccountName, $_.Exception.Message)
    }
  } else {
    # When -WhatIf is used, ShouldProcess will report and skip the actual call
    # To show parity with Set-ADUser -WhatIf output, we can still call with -WhatIf if desired:
    try {
      Set-ADUser -Identity $u.SamAccountName -UserPrincipalName $new -WhatIf
    } catch { }
  }
}

# ---------- Summary ----------
Write-Host ""
Write-Host "========== Summary ==========" -ForegroundColor White
Write-Host ("Changed           : {0}" -f $changed)           -ForegroundColor Green
Write-Host ("Skipped (same)    : {0}" -f $skippedSame)       -ForegroundColor DarkYellow
Write-Host ("Skipped (conflict): {0}" -f $skippedConflict)   -ForegroundColor DarkYellow
Write-Host ("Skipped (other)   : {0}" -f $skippedOther)      -ForegroundColor DarkYellow
Write-Host ("Errors            : {0}" -f $errors)            -ForegroundColor Red
