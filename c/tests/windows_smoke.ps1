# Runs vex's Windows programs on a real Windows machine and checks that they
# behave: the native window opens, shows the page, and closing it ends the
# program. Used by .github/workflows/windows-test.yml.
#
#   pwsh c/tests/windows_smoke.ps1 -Dir FOLDER_WITH_THE_PROGRAMS -Out FOLDER_FOR_RESULTS
param([Parameter(Mandatory)][string]$Dir, [string]$Out = "smoke-output")

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$Dir = (Resolve-Path $Dir).Path
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:failures = @()
function Check([string]$Name, [bool]$Ok, [string]$Detail = "") {
    $mark = if ($Ok) { "PASS" } else { "FAIL" }
    Write-Host "[$mark] $Name $Detail"
    if (-not $Ok) { $script:failures += $Name }
}

# A picture of the whole screen, saved as PNG, and a small JPEG copy written
# into the log as base64 so it can be read back without downloading anything.
function Save-Screenshot([string]$Name) {
    try {
        $area = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $shot = New-Object System.Drawing.Bitmap $area.Width, $area.Height
        $pen = [System.Drawing.Graphics]::FromImage($shot)
        $pen.CopyFromScreen($area.Left, $area.Top, 0, 0, $shot.Size)
        $pen.Dispose()
        $shot.Save((Join-Path $Out "$Name.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        $width = 1000
        $height = [int]($area.Height * $width / $area.Width)
        $small = New-Object System.Drawing.Bitmap $shot, $width, $height
        $jpeg = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
            Where-Object { $_.MimeType -eq "image/jpeg" }
        $quality = New-Object System.Drawing.Imaging.EncoderParameters 1
        $quality.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter `
            ([System.Drawing.Imaging.Encoder]::Quality), 55L
        $small.Save((Join-Path $Out "$Name.jpg"), $jpeg, $quality)
        $small.Dispose(); $shot.Dispose()
        $text = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $Out "$Name.jpg")),
                                          [Base64FormattingOptions]::InsertLineBreaks)
        Write-Host "-----BEGIN SCREENSHOT $Name-----"
        Write-Host $text
        Write-Host "-----END SCREENSHOT $Name-----"
    } catch {
        Write-Host "(no screenshot: $($_.Exception.Message))"
    }
}

function Get-WebView2Version {
    $id = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    foreach ($key in "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$id",
                     "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$id",
                     "HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$id") {
        try {
            $version = (Get-ItemProperty -Path $key -ErrorAction Stop).pv
            if ($version) { return $version }
        } catch { }
    }
    return $null
}

# Wait until the program's main window carries the wanted title.
function Wait-ForTitle($Process, [string]$Wanted, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    $title = ""
    while ((Get-Date) -lt $deadline) {
        $Process.Refresh()
        if ($Process.HasExited) { break }
        $title = $Process.MainWindowTitle
        if ($title -like $Wanted) { break }
        Start-Sleep -Milliseconds 500
    }
    return $title
}

function Close-AndCheck($Process, [string]$What) {
    $null = $Process.CloseMainWindow()
    $ended = $Process.WaitForExit(20000)
    Check "$What`: closing the window ends the program" $ended
    if ($ended) {
        Check "$What`: exit status 0" ($Process.ExitCode -eq 0) "(status $($Process.ExitCode))"
    } else {
        $Process.Kill()
    }
}

Write-Host "Windows: $([Environment]::OSVersion.VersionString)"
$runtime = Get-WebView2Version
Write-Host "WebView2 runtime: $(if ($runtime) { $runtime } else { 'NOT INSTALLED' })"

# --- the native window on its own -------------------------------------------
$log = Join-Path $Out "probe-window.log"
$env:VEX_WINDOW_LOG = $log
$probe = Start-Process -FilePath (Join-Path $Dir "appwin-probe.exe") -PassThru
$null = $probe.Handle                   # keeps the exit status readable later
$title = Wait-ForTitle $probe "vex probe" 60
Start-Sleep -Seconds 2
Save-Screenshot "probe"
Check "probe: the window opened and shows the page" ($title -eq "vex probe") `
    "(title '$title', exited: $($probe.HasExited))"
if ($probe.HasExited) {
    Write-Host "probe exit status: $($probe.ExitCode)"
} else {
    Close-AndCheck $probe "probe"
}
Write-Host "--- window log (probe) ---"
if (Test-Path $log) { Get-Content $log } else { Write-Host "(nothing was logged)" }
$env:VEX_WINDOW_LOG = $null

Write-Host ""
if ($script:failures.Count -gt 0) {
    Write-Host "FAILED: $($script:failures -join '; ')"
    exit 1
}
Write-Host "All checks passed."
