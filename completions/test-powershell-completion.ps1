# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# Unit tests for the generated PowerShell completion (nvme-completion.ps1).
#
# The completion under test is generated fresh from a committed metadata fixture
# rather than sourced from the checked-in nvme-completion.ps1: the generator is
# the unit under test, so we exercise its current output. The fixture
# (test-command-metadata.json) is a hand-written, schema-validated model of
# synthetic commands and options -- deliberately not real nvme output -- built to
# exercise every generator branch, and needs no nvme binary or build.
#
# PowerShell's Register-ArgumentCompleter drives completion via the framework, so
# we test by calling TabExpansion2 against the loaded completer and inspecting the
# CompletionResult list.

$ErrorActionPreference = 'Stop'

# PowerShell has no '< file' stdin redirection, so pipe the fixture into the
# generator (which reads JSON on stdin and writes the completer to its path arg).
$python = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python -ErrorAction SilentlyContinue }
if (-not $python) { Write-Error 'python3 not found'; exit 1 }

$generated = Join-Path ([System.IO.Path]::GetTempPath()) `
    ("nvme-completion-{0}.ps1" -f [System.IO.Path]::GetRandomFileName())
Get-Content -Raw "$PSScriptRoot/test-command-metadata.json" |
    & $python.Source "$PSScriptRoot/generate-completions.py" --powershell $generated
if ($LASTEXITCODE -ne 0) { Write-Error 'failed to generate PowerShell completion from fixture'; exit 1 }
. $generated
Remove-Item $generated -ErrorAction SilentlyContinue

$script:TestsRun = 0
$script:TestsPassed = 0
$script:TestsFailed = 0

function Get-Completions {
    param([string]$InputScript)
    $result = TabExpansion2 -inputScript $InputScript -cursorColumn $InputScript.Length
    if ($null -eq $result -or $null -eq $result.CompletionMatches) {
        return @()
    }
    return @($result.CompletionMatches | ForEach-Object { $_.CompletionText })
}

function Assert-Match {
    param([string]$Desc, [string]$InputScript, [string]$Pattern)
    $script:TestsRun++
    $completions = Get-Completions $InputScript
    $joined = $completions -join ' '
    if ($joined -match $Pattern) {
        Write-Host "  PASS: $Desc" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  FAIL: $Desc" -ForegroundColor Red
        Write-Host "    Input: '$InputScript'" -ForegroundColor Yellow
        Write-Host "    Expected match: /$Pattern/" -ForegroundColor Yellow
        Write-Host "    Got: '$joined'" -ForegroundColor Yellow
        $script:TestsFailed++
    }
}

function Assert-NoMatch {
    param([string]$Desc, [string]$InputScript, [string]$Pattern)
    $script:TestsRun++
    $completions = Get-Completions $InputScript
    $joined = $completions -join ' '
    if ($joined -match $Pattern) {
        Write-Host "  FAIL: $Desc" -ForegroundColor Red
        Write-Host "    Input: '$InputScript'" -ForegroundColor Yellow
        Write-Host "    Should not match: /$Pattern/" -ForegroundColor Yellow
        Write-Host "    Got: '$joined'" -ForegroundColor Yellow
        $script:TestsFailed++
    } else {
        Write-Host "  PASS: $Desc" -ForegroundColor Green
        $script:TestsPassed++
    }
}

Write-Host "========================================"
Write-Host "PowerShell Completion Tests"
Write-Host "========================================"
Write-Host ""

# ---------------------------------------------------------------------------
# Top-level command dispatch
# ---------------------------------------------------------------------------
Write-Host "Top-level command dispatch:"

Assert-Match `
    "top-level list offers builtin commands" `
    "nvme " `
    "\balpha-cmd\b"

Assert-Match `
    "top-level list includes plugin names" `
    "nvme " `
    "\bzeta-plug\b"

# A command alias is listed alongside its primary name (alpha-alias is an alias
# of zulu-cmd).
Assert-Match `
    "top-level list includes a command alias" `
    "nvme " `
    "\balpha-alias\b"

Assert-Match `
    "top-level list includes help" `
    "nvme " `
    "\bhelp\b"

Assert-Match `
    "top-level list includes version" `
    "nvme " `
    "\bversion\b"

Assert-Match `
    "prefix narrows the top-level list" `
    "nvme alpha-" `
    "\balpha-cmd\b"

Assert-NoMatch `
    "prefix excludes non-matching commands" `
    "nvme alpha-" `
    "\bzulu-cmd\b"

Write-Host ""

# ---------------------------------------------------------------------------
# Plugin sub-command listing
# ---------------------------------------------------------------------------
Write-Host "Plugin sub-command listing:"

Assert-Match `
    "a plugin lists its sub-commands" `
    "nvme zeta-plug " `
    "\breport\b"

# A different plugin, to prove sub-command routing isn't hardcoded to one name.
Assert-Match `
    "sub-command routing works for any plugin" `
    "nvme beta-plug " `
    "\blocal-sub\b"

# A plugin sub-command alias is listed alongside its primary name (zeta-plug
# defines alias 'rpt' for 'report').
Assert-Match `
    "a plugin lists a sub-command alias" `
    "nvme zeta-plug " `
    "\brpt\b"

Write-Host ""

# ---------------------------------------------------------------------------
# Option-name completion
# ---------------------------------------------------------------------------
Write-Host "Option-name completion:"

Assert-Match `
    "a builtin command offers its options" `
    "nvme alpha-cmd --wait-" `
    "--wait-time"

# A command invoked by its alias completes the same options (alpha-alias is an
# alias of zulu-cmd).
Assert-Match `
    "a command invoked by alias completes options" `
    "nvme alpha-alias --m" `
    "--mode"

Assert-Match `
    "a plugin sub-command offers its options" `
    "nvme zeta-plug report --s" `
    "--sel"

Assert-Match `
    "all options listed for a command (space trigger)" `
    "nvme alpha-cmd " `
    "--format"

Assert-Match `
    "short options are offered" `
    "nvme alpha-cmd " `
    "(^| )-o( |$)"

Assert-Match `
    "--help is always offered" `
    "nvme alpha-cmd --hel" `
    "--help"

# A hidden option is accepted on the command line but suppressed from --help, so
# the generator must not offer it as a completion (zulu-cmd has a hidden 'secret').
Assert-NoMatch `
    "a hidden option is not offered" `
    "nvme zulu-cmd -" `
    "--secret"

Write-Host ""

# ---------------------------------------------------------------------------
# help / version built-ins
# ---------------------------------------------------------------------------
Write-Host "help / version built-ins:"

Assert-Match `
    "help completes a command name" `
    "nvme help " `
    "\balpha-cmd\b"

# Note: 'nvme help alpha-cmd <TAB>' and 'nvme version <TAB>' -- our completer
# returns nothing (correct), but PowerShell's framework falls back to file
# completion which we cannot suppress from a native-command completer.

Write-Host ""

# ---------------------------------------------------------------------------
# Option-value completion (enumerated values)
# ---------------------------------------------------------------------------
Write-Host "Option-value completion:"

Assert-Match `
    "a value option lists its values (long opt)" `
    "nvme alpha-cmd --format " `
    "raw.*pretty.*wide"

Assert-Match `
    "a value option lists its values (short opt)" `
    "nvme alpha-cmd -o " `
    "raw.*pretty.*wide"

# --sel values come from the generator's VALUE_HINTS table, reached through the
# plugin sub-command routing path.
Assert-Match `
    "a value option on a plugin sub-command (--sel)" `
    "nvme zeta-plug report --sel " `
    "0.*1.*2.*3"

Assert-Match `
    "a value option on a plugin sub-command (short opt)" `
    "nvme zeta-plug report -S " `
    "0.*1.*2.*3"

# A command-local enumerated option whose values come from the metadata
# (local-sub --mode carries a value set).
Assert-Match `
    "a command-local enumerated option lists its values" `
    "nvme beta-plug local-sub --mode " `
    "fast.*slow"

Assert-Match `
    "--opt=value attached form lists values" `
    "nvme alpha-cmd --format=" `
    "--format=raw.*--format=pretty"

Write-Host ""

# ---------------------------------------------------------------------------
# File-valued options (metavar FILE/DIRECTORY)
# ---------------------------------------------------------------------------
Write-Host "File-valued options:"

# File completion enumerates the real filesystem (Get-ChildItem), so seed a temp
# directory with a known file and complete from there: a file-valued option must
# then offer that file, and an enumerated option must not. Asserting the sentinel
# name -- rather than "any output" -- is deterministic and independent of cwd.
$fileDir = Join-Path ([System.IO.Path]::GetTempPath()) `
    ("nvme-filetest-{0}" -f [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $fileDir | Out-Null
$sentinel = 'fixture-sentinel-file'
New-Item -ItemType File -Path (Join-Path $fileDir $sentinel) | Out-Null
Push-Location $fileDir
try {
    Assert-Match `
        "a file-valued option completes filenames (long opt)" `
        "nvme alpha-cmd --in-file " `
        $sentinel

    Assert-Match `
        "a file-valued option completes filenames (short opt)" `
        "nvme alpha-cmd -f " `
        $sentinel

    # A DIRECTORY-valued option is treated the same as FILE (report --out-dir).
    Assert-Match `
        "a directory-valued option completes filenames" `
        "nvme zeta-plug report --out-dir " `
        $sentinel

    # An enumerated option lists its values, never the filesystem -- so even with
    # the seeded file present it must not be offered.
    Assert-NoMatch `
        "an enumerated option does not offer files" `
        "nvme alpha-cmd --format " `
        $sentinel
} finally {
    Pop-Location
    Remove-Item $fileDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""

# ---------------------------------------------------------------------------
# Device argument hint
# ---------------------------------------------------------------------------
Write-Host "Device argument hint:"

Assert-Match `
    "a command offers /dev/nvme as a device hint" `
    "nvme alpha-cmd " `
    "/dev/nvme"

Assert-Match `
    "typing /dev narrows to the device hint" `
    "nvme alpha-cmd /dev" `
    "/dev/nvme"

Write-Host ""

# ---------------------------------------------------------------------------
# Alphabetical sorting
# ---------------------------------------------------------------------------
Write-Host "Alphabetical sorting:"

function Test-OrdinalSorted {
    param([string[]]$Items)
    for ($i = 1; $i -lt $Items.Count; $i++) {
        if ([string]::CompareOrdinal($Items[$i-1], $Items[$i]) -gt 0) {
            return $false
        }
    }
    return $true
}

$script:TestsRun++
$completions = Get-Completions "nvme "
if (Test-OrdinalSorted $completions) {
    Write-Host "  PASS: top-level commands are sorted" -ForegroundColor Green
    $script:TestsPassed++
} else {
    Write-Host "  FAIL: top-level commands are not sorted" -ForegroundColor Red
    $script:TestsFailed++
}

$script:TestsRun++
$completions = Get-Completions "nvme alpha-cmd "
# Exclude short options and /dev/nvme hint; --help is appended last by design.
$optOnly = @($completions | Where-Object { $_ -like '--*' -and $_ -ne '--help' })
if (Test-OrdinalSorted $optOnly) {
    Write-Host "  PASS: long options are sorted" -ForegroundColor Green
    $script:TestsPassed++
} else {
    Write-Host "  FAIL: long options are not sorted" -ForegroundColor Red
    Write-Host "    Got: $($optOnly -join ', ')" -ForegroundColor Yellow
    $script:TestsFailed++
}

Write-Host ""

# ---------------------------------------------------------------------------
# Global options are per-command (not every command has them)
# ---------------------------------------------------------------------------
Write-Host "Per-command global options:"

# alpha-cmd carries the global 'format' option; local-sub carries no globals.
Assert-Match `
    "a command with global options offers them" `
    "nvme alpha-cmd -" `
    "--format"

Assert-NoMatch `
    "a command without global options is not offered them" `
    "nvme beta-plug local-sub -" `
    "--format"

Write-Host ""

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "========================================"
Write-Host "Results: $($script:TestsPassed)/$($script:TestsRun) passed"
if ($script:TestsFailed -gt 0) {
    Write-Host "$($script:TestsFailed) tests failed" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All tests passed" -ForegroundColor Green
    exit 0
}
