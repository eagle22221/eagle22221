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

# A picture of the whole screen, saved as PNG in the results folder.
function Save-Screenshot([string]$Name) {
    try {
        $area = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $shot = New-Object System.Drawing.Bitmap $area.Width, $area.Height
        $pen = [System.Drawing.Graphics]::FromImage($shot)
        $pen.CopyFromScreen($area.Left, $area.Top, 0, 0, $shot.Size)
        $pen.Dispose()
        $shot.Save((Join-Path $Out "$Name.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        $shot.Dispose()
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

# Wait until the program's main window carries the wanted title, reporting the
# web view's helper processes along the way.
function Wait-ForTitle($Process, [string]$Wanted, [int]$Seconds) {
    $start = Get-Date
    $deadline = $start.AddSeconds($Seconds)
    $title = ""
    $nextReport = $start.AddSeconds(5)
    while ((Get-Date) -lt $deadline) {
        $Process.Refresh()
        if ($Process.HasExited) { break }
        $title = $Process.MainWindowTitle
        if ($title -like $Wanted) { break }
        if ((Get-Date) -ge $nextReport) {
            $helpers = @(Get-Process -Name msedgewebview2 -ErrorAction SilentlyContinue).Count
            Write-Host ("  ...{0,3:N0} s: title '{1}', {2} web view processes" -f `
                ((Get-Date) - $start).TotalSeconds, $title, $helpers)
            $nextReport = (Get-Date).AddSeconds(10)
        }
        Start-Sleep -Milliseconds 500
    }
    Write-Host ("  waited {0:N1} s" -f ((Get-Date) - $start).TotalSeconds)
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
# Run the probe once per setting, to tell apart the ways start-up can go wrong.
function Test-Probe([string]$Name, [hashtable]$Settings) {
    Write-Host ""
    Write-Host "=== probe: $Name ==="
    $log = Join-Path $Out "probe-$Name.log"
    $env:VEX_WINDOW_LOG = $log
    foreach ($key in $Settings.Keys) { Set-Item -Path "env:$key" -Value $Settings[$key] }
    $probe = Start-Process -FilePath (Join-Path $Dir "appwin-probe.exe") -PassThru
    $null = $probe.Handle               # keeps the exit status readable later
    $title = Wait-ForTitle $probe "vex probe" 150
    Start-Sleep -Seconds 2
    Save-Screenshot "probe-$Name"
    Check "probe ($Name): the window opened and shows the page" ($title -eq "vex probe") `
        "(title '$title', exited: $($probe.HasExited))"
    if ($probe.HasExited) {
        Write-Host "probe exit status: $($probe.ExitCode)"
    } else {
        Close-AndCheck $probe "probe ($Name)"
    }
    Write-Host "--- window log ---"
    if (Test-Path $log) { Get-Content $log } else { Write-Host "(nothing was logged)" }
    foreach ($key in $Settings.Keys) { Remove-Item -Path "env:$key" }
    $env:VEX_WINDOW_LOG = $null
    Get-Process -Name msedgewebview2 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

Test-Probe "first-start" @{ VEX_WINDOW_TIMEOUT_MS = "120000" }
Test-Probe "second-start" @{ }

Write-Host ""
if ($script:failures.Count -gt 0) {
    Write-Host "FAILED: $($script:failures -join '; ')"
    exit 1
}
Write-Host "All checks passed."
