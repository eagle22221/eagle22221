# Runs vex's Windows programs on a Windows PC and checks that they behave: the
# native window opens, shows the page, and closing it ends the program.
# Screenshots and window logs are saved in the results folder.
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

# --- the command-line program -----------------------------------------------
$vex = Join-Path $Dir "vex.exe"
$app = Join-Path $Dir "vex-app.exe"
$sample = Join-Path $Dir "practice\hello_pe64.exe"

if (Test-Path $vex) {
    Write-Host ""
    Write-Host "=== vex.exe: commands ==="
    $text = (& $vex --version) -join "`n"
    Check "vex.exe --version" ($LASTEXITCODE -eq 0 -and $text -match "vex") "($text)"
    $text = (& $vex info $sample) -join "`n"
    Check "vex.exe info" ($LASTEXITCODE -eq 0 -and $text -match "Windows executable")
    $text = (& $vex imports $sample) -join "`n"
    Check "vex.exe imports" ($LASTEXITCODE -eq 0 -and $text -match "KERNEL32")
    $text = (& $vex disasm $sample entry) -join "`n"
    Check "vex.exe disasm" ($LASTEXITCODE -eq 0 -and $text -match "call")
    $text = (& $vex techniques (Join-Path $Dir "practice\evasion_pe64.exe")) -join "`n"
    Check "vex.exe techniques" ($LASTEXITCODE -eq 0 -and $text -match "(?i)anti-debug")
    $text = (& $vex decode --text "SGVsbG8=" --recipe "from-base64") -join "`n"
    Check "vex.exe decode" ($LASTEXITCODE -eq 0 -and $text -match "Hello")
    $parts = Join-Path $Out "bundle_parts"
    $null = & $vex split (Join-Path $Dir "practice\bundle_pe64.exe") $parts
    $embedded = @(Get-ChildItem (Join-Path $parts "embedded") -ErrorAction SilentlyContinue).Count
    Check "vex.exe split" ($LASTEXITCODE -eq 0 -and (Test-Path (Join-Path $parts "index.txt")) -and $embedded -eq 3) `
        "($embedded embedded files)"
    $null = & $vex info (Join-Path $Dir "no-such-file.exe") 2>&1
    Check "vex.exe reports a missing file" ($LASTEXITCODE -ne 0) "(status $LASTEXITCODE)"
}

# --- the windowed program ---------------------------------------------------
# Start a program, wait for a window titled like $Wanted, take a picture, close
# the window and check the program ends.
function Test-Window([string]$Name, [string]$File, [string[]]$Arguments, [string]$Wanted,
                     [string]$Folder = $Dir) {
    Write-Host ""
    Write-Host "=== $Name ==="
    $log = Join-Path $Out "$Name-window.log"
    $env:VEX_WINDOW_LOG = $log
    $start = @{ FilePath = $File; PassThru = $true; WorkingDirectory = $Folder }
    if ($Arguments.Count -gt 0) { $start.ArgumentList = $Arguments }
    $process = Start-Process @start
    $null = $process.Handle
    $title = Wait-ForTitle $process $Wanted 150
    Start-Sleep -Seconds 3              # let the page finish drawing
    Save-Screenshot $Name
    Check "$Name`: its own window opened with the page in it" ($title -like $Wanted) `
        "(title '$title', exited: $($process.HasExited))"
    if ($process.HasExited) {
        Write-Host "exit status: $($process.ExitCode)"
    } else {
        Close-AndCheck $process $Name
    }
    Write-Host "--- window log ---"
    if (Test-Path $log) { Get-Content $log } else { Write-Host "(nothing was logged)" }
    $env:VEX_WINDOW_LOG = $null
}

if (Test-Path $app) {
    # The file's name in the title means the whole chain worked: the server
    # inside the program, the page, and the page's requests back to the server.
    Test-Window "app-with-file" $app @("`"$sample`"") "hello_pe64.exe*vex"
    Test-Window "app-start-page" $app @() "vex"
    Test-Window "console-gui" $vex @("gui", "`"$sample`"") "hello_pe64.exe*vex"
    $left = @(Get-Process -Name "vex-app", "vex" -ErrorAction SilentlyContinue).Count
    Check "no vex process is left running" ($left -eq 0) "($left left)"

    # Without the loader next to it the program must still come up, in an
    # app-mode Edge window, and stop when that window is closed.
    Write-Host ""
    Write-Host "=== app-without-loader (falls back to an Edge app window) ==="
    $bare = Join-Path $Out "no-loader"
    New-Item -ItemType Directory -Force $bare | Out-Null
    Copy-Item $app $bare
    $log = Join-Path $Out "app-without-loader-window.log"
    $env:VEX_WINDOW_LOG = $log
    $process = Start-Process -FilePath (Join-Path $bare "vex-app.exe") -ArgumentList "`"$sample`"" -PassThru
    $null = $process.Handle
    $edge = $null
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline -and -not $edge -and -not $process.HasExited) {
        Start-Sleep -Seconds 1
        $edge = Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" |
            Where-Object { $_.CommandLine -like "*--app=http://127.0.0.1*" -and $_.CommandLine -notlike "*--type=*" } |
            Select-Object -First 1
        $process.Refresh()
    }
    Check "app-without-loader: an Edge app window was started" ($null -ne $edge)
    if ($edge) {
        $window = Get-Process -Id $edge.ProcessId
        $null = Wait-ForTitle $window "hello_pe64.exe*vex" 90
        Start-Sleep -Seconds 3
        Save-Screenshot "app-without-loader"
        $window.Refresh()
        Check "app-without-loader: the page loaded in it" ($window.MainWindowTitle -like "hello_pe64.exe*vex") `
            "(title '$($window.MainWindowTitle)')"
        $profiles = @(Get-ChildItem $env:TEMP -Filter "vex-window-*" -Directory -ErrorAction SilentlyContinue)
        Check "app-without-loader: it uses a profile of its own" ($profiles.Count -ge 1)
        $null = $window.CloseMainWindow()
        $ended = $process.WaitForExit(30000)
        Check "app-without-loader: closing the window ends the program" $ended
        if ($ended) {
            Check "app-without-loader: exit status 0" ($process.ExitCode -eq 0) "(status $($process.ExitCode))"
            Start-Sleep -Seconds 1
            $profiles = @(Get-ChildItem $env:TEMP -Filter "vex-window-*" -Directory -ErrorAction SilentlyContinue)
            Check "app-without-loader: the profile was deleted" ($profiles.Count -eq 0) "($($profiles.Count) left)"
        }
    }
    if (-not $process.HasExited) { $process.Kill() }
    Write-Host "--- window log ---"
    if (Test-Path $log) { Get-Content $log } else { Write-Host "(nothing was logged)" }
    $env:VEX_WINDOW_LOG = $null
}

Write-Host ""
if ($script:failures.Count -gt 0) {
    Write-Host "FAILED: $($script:failures -join '; ')"
    exit 1
}
Write-Host "All checks passed."
