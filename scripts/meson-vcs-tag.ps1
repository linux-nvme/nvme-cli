#!/usr/bin/env pwsh
# SPDX-License-Identifier: LGPL-2.1-or-later

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Directory,

    [Parameter(Mandatory=$true, Position=1)]
    [string]$Fallback
)

$ErrorActionPreference = "Stop"

# Apparently git describe has a bug where it always considers the work-tree
# dirty when invoked with --git-dir (even though 'git status' is happy). Work
# around this issue by cd-ing to the source directory.
Push-Location $Directory

try {
    # Check that we have either .git/ (a normal clone) or a .git file (a work-tree)
    # and that we don't get confused if a tarball is extracted in a higher-level
    # git repository.
    if (Test-Path ".git") {
        try {
            $version = git describe --abbrev=7 --dirty=+ 2>&1
            if ($LASTEXITCODE -eq 0) {
                # Remove leading 'v' if present
                $version = $version -replace '^v', ''
                Write-Output $version
            } else {
                Write-Output $Fallback
            }
        } catch {
            Write-Output $Fallback
        }
    } else {
        Write-Output $Fallback
    }
} finally {
    Pop-Location
}
