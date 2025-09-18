<# 
.SYNOPSIS
  Scan QCSV logs for rows in the last N minutes (UTC),
  flag any row containing "error" (case-insensitive, any field), and email alerts.

.PARAMETERS
  -MinutesBack   Time window (minutes) to scan backwards from now (UTC). Default: 5
  -Batch         If present, send a single email with all matches this run (default: one email per row).

.NOTES
  - Relies on timestamp in column 1 (UTC, e.g., 2025-09-18T21:03:51.176).
#>

param(
  [int]$MinutesBack = 5,
  [switch]$Batch
)

# -------------------- static config --------------------
$LogDirectory   = "C:\logs"
$FilePattern    = "*.csv"

# Email settings (static)
$SmtpServer     = "smtp.domain.com"
$SmtpPort       = 25
$UseSsl         = $false
$From           = "user@domain.com"
$To             = @("user@domain.com","user2@domain.com")
$SubjectPrefix  = "[CSV LogWatch]"

# -------------------- helpers --------------------

function Get-TargetCsv {
  if (-not (Test-Path $LogDirectory)) { throw "Log directory not found: $LogDirectory" }
  $today = (Get-Date).Date
  $files = Get-ChildItem -Path $LogDirectory -Filter $FilePattern -File -ErrorAction Stop
  if (-not $files) { return $null }
  $todays = $files | Where-Object { $_.LastWriteTime.Date -eq $today }
  if ($todays) { $todays | Sort-Object LastWriteTime -Descending | Select-Object -First 1 }
  else { $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1 }
}

function Read-AllTextShared([string]$path) {
  $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')  # allow writer to continue
  try {
    $sr = New-Object System.IO.StreamReader($fs, $true)
    try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
  } finally { $fs.Dispose() }
}

# Parse first-column timestamps as UTC (supports with/without milliseconds)
function TryParse-Timestamp([string]$s, [ref]$dtOut) {
  $provider = [System.Globalization.CultureInfo]::InvariantCulture
  $style    = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor `
              [System.Globalization.DateTimeStyles]::AdjustToUniversal

  $tmp = [datetime]::MinValue
  if ([datetime]::TryParseExact($s, "yyyy-MM-dd'T'HH:mm:ss.fff", $provider, $style, [ref]$tmp)) {
    $dtOut.Value = $tmp
    return $true
  }
  if ([datetime]::TryParseExact($s, "yyyy-MM-dd'T'HH:mm:ss", $provider, $style, [ref]$tmp)) {
    $dtOut.Value = $tmp
    return $true
  }
  return $false
}

function Send-AlertMail([string]$subject, [string]$body) {
  $mailParams = @{
    To         = $To
    From       = $From
    Subject    = $subject
    Body       = $body
    SmtpServer = $SmtpServer
    Port       = $SmtpPort
    UseSsl     = $UseSsl
    BodyAsHtml = $false
  }
  # Windows PowerShell has Send-MailMessage. For PowerShell 7+, swap to MailKit/Graph if needed.
  Send-MailMessage @mailParams
}

# -------------------- main --------------------

$csvFile = Get-TargetCsv
if (-not $csvFile) { return }

$nowUtc = [datetime]::UtcNow
$windowStart = $nowUtc.AddMinutes(-1 * [math]::Abs($MinutesBack))

$text = Read-AllTextShared -path $csvFile.FullName
if ([string]::IsNullOrWhiteSpace($text)) { return }

$lines = $text -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 }

# Keep rows whose first field timestamp (UTC) is within the window
$recentLines = foreach ($line in $lines) {
  $firstComma = $line.IndexOf(',')
  if ($firstComma -lt 0) { continue }  # header/malformed
  $tsString = $line.Substring(0, $firstComma)

  $dtUtc = $null
  if (TryParse-Timestamp $tsString ([ref]$dtUtc)) {
    if ($dtUtc -ge $windowStart -and $dtUtc -le $nowUtc.AddSeconds(1)) { $line }
  }
}

if (-not $recentLines -or $recentLines.Count -eq 0) { return }

# From recent rows, find any containing 'error' anywhere (any field)
$errLines = $recentLines | Where-Object { $_ -match '(?i)error' }
if (-not $errLines -or $errLines.Count -eq 0) { return }

# Send alerts
$tsLocal = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
if ($Batch) {
  $subject = "$SubjectPrefix errors in $($csvFile.Name) @ $tsLocal"
  $body = @(
    "File: $($csvFile.FullName)"
    "UTC Window: $($windowStart.ToString('yyyy-MM-dd HH:mm:ss')) to $($nowUtc.ToString('yyyy-MM-dd HH:mm:ss'))"
    "Matches (CSV rows):"
    "-----------------------------"
    ($errLines -join [Environment]::NewLine)
  ) -join [Environment]::NewLine
  Send-AlertMail -subject $subject -body $body
} else {
  foreach ($line in $errLines) {
    $subject = "$SubjectPrefix error in $($csvFile.Name)"
    $body = @(
      "File: $($csvFile.FullName)"
      "Local When: $tsLocal"
      "UTC Window: $($windowStart.ToString('yyyy-MM-dd HH:mm:ss')) to $($nowUtc.ToString('yyyy-MM-dd HH:mm:ss'))"
      "CSV Row:"
      $line
    ) -join [Environment]::NewLine
    Send-AlertMail -subject $subject -body $body
  }
}
