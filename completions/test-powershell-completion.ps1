# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 Micron Technology, Inc.
#
# Unit tests for the generated PowerShell completion (nvme-completion.ps1).
#
# PowerShell's Register-ArgumentCompleter drives completion via the framework,
# so we test by calling TabExpansion2 against the loaded completer and
# inspecting the CompletionResult list.

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/nvme-completion.ps1"

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

function Assert-Empty {
    param([string]$Desc, [string]$InputScript)
    $script:TestsRun++
    $completions = Get-Completions $InputScript
    if ($completions.Count -eq 0) {
        Write-Host "  PASS: $Desc" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host "  FAIL: $Desc" -ForegroundColor Red
        Write-Host "    Input: '$InputScript'" -ForegroundColor Yellow
        Write-Host "    Expected nothing, got: '$($completions -join ' ')'" -ForegroundColor Yellow
        $script:TestsFailed++
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
    "\blist\b"

Assert-Match `
    "top-level list includes plugin names" `
    "nvme " `
    "feat"

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
    "nvme li" `
    "\blist\b"

Assert-NoMatch `
    "prefix excludes non-matching commands" `
    "nvme li" `
    "\bformat\b"

Write-Host ""

# ---------------------------------------------------------------------------
# Plugin sub-command listing
# ---------------------------------------------------------------------------
Write-Host "Plugin sub-command listing:"

Assert-Match `
    "a plugin lists its sub-commands" `
    "nvme feat " `
    "power-mgmt"

Assert-Match `
    "sub-command routing works for any plugin" `
    "nvme ocp " `
    "smart-add-log"

Assert-Match `
    "a plugin lists a sub-command alias" `
    "nvme dera " `
    "stat"

Write-Host ""

# ---------------------------------------------------------------------------
# Option-name completion
# ---------------------------------------------------------------------------
Write-Host "Option-name completion:"

Assert-Match `
    "a builtin command offers its options" `
    "nvme list --out" `
    "--output-format"

Assert-Match `
    "a command invoked by alias completes options" `
    "nvme fw activate --a" `
    "--action"

Assert-Match `
    "a plugin sub-command offers its options" `
    "nvme feat power-meas --s" `
    "--sel"

Assert-Match `
    "all options listed for a command (space trigger)" `
    "nvme list " `
    "--output-format"

Assert-Match `
    "short options are offered" `
    "nvme list " `
    "(^| )-o( |$)"

Assert-Match `
    "--help is always offered" `
    "nvme list --hel" `
    "--help"

Write-Host ""

# ---------------------------------------------------------------------------
# help / version built-ins
# ---------------------------------------------------------------------------
Write-Host "help / version built-ins:"

Assert-Match `
    "help completes a command name" `
    "nvme help " `
    "\blist\b"

# Note: 'nvme help list <TAB>' and 'nvme version <TAB>' -- our completer
# returns nothing (correct), but PowerShell's framework falls back to file
# completion which we cannot suppress from a native-command completer.

Write-Host ""

# ---------------------------------------------------------------------------
# Option-value completion (enumerated values)
# ---------------------------------------------------------------------------
Write-Host "Option-value completion:"

Assert-Match `
    "a value option lists its values (long opt)" `
    "nvme list --output-format " `
    "normal.*json.*binary.*tabular"

Assert-Match `
    "a value option lists its values (short opt)" `
    "nvme list -o " `
    "normal.*json.*binary.*tabular"

Assert-Match `
    "a value option on a plugin sub-command (--sel)" `
    "nvme feat power-meas --sel " `
    "0.*1.*2.*3"

Assert-Match `
    "a value option on a plugin sub-command (short opt)" `
    "nvme feat power-meas -S " `
    "0.*1.*2.*3"

Assert-Match `
    "a command-local enumerated option lists its values" `
    "nvme fw commit --action " `
    "replace.*set-active"

Assert-Match `
    "--opt=value attached form lists values" `
    "nvme list --output-format=" `
    "output-format=normal.*output-format=json"

Write-Host ""

# ---------------------------------------------------------------------------
# File-valued options (metavar FILE/DIRECTORY)
# ---------------------------------------------------------------------------
Write-Host "File-valued options:"

Assert-Match `
    "a file-valued option completes filenames (long opt)" `
    "nvme fw download --fw " `
    "."

Assert-Match `
    "a file-valued option completes filenames (short opt)" `
    "nvme fw download -f " `
    "."

Assert-NoMatch `
    "an enumerated option does not offer files" `
    "nvme list --output-format " `
    "\\\\|/"

Write-Host ""

# ---------------------------------------------------------------------------
# Device argument hint
# ---------------------------------------------------------------------------
Write-Host "Device argument hint:"

Assert-Match `
    "a command offers /dev/nvme as a device hint" `
    "nvme list " `
    "/dev/nvme"

Assert-Match `
    "typing /dev narrows to the device hint" `
    "nvme list /dev" `
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
$completions = Get-Completions "nvme list "
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

Assert-Match `
    "a command with global options offers them" `
    "nvme list --verb" `
    "--verbose"

Assert-NoMatch `
    "a command without global options is not offered them" `
    "nvme intel lat-stats-tracking --output" `
    "--output-format"

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
