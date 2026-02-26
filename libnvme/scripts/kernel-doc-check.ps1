
# SPDX-License-Identifier: LGPL-2.1-or-later

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$kernelDoc = Join-Path $scriptDir "kernel-doc"

# Check if perl is available
$perl = Get-Command perl -ErrorAction SilentlyContinue
if (-not $perl) {
    Write-Error "Perl is not installed or not in PATH."
    exit 1
}

# Run kernel-doc and capture output and exit code
$output = & perl $kernelDoc -none $args 2>&1
$kernelDocExitCode = $LASTEXITCODE

# Filter for warnings and errors
$filtered = $output | Select-String -Pattern '(warning|error)'

# Check that kernel-doc succeeded (exit code 0) and no warnings/errors were found
if ($kernelDocExitCode -eq 0 -and $filtered.Count -eq 0) {
    exit 0
} else {
    # Print any warnings/errors found
    $filtered | ForEach-Object { Write-Host $_ }
    exit 1
}
