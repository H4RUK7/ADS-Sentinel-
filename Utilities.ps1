<#
.SYNOPSIS
    ADS Sentinel Utility Functions
.DESCRIPTION
    Shared utility functions for ADS Sentinel components
#>

# Stream utility functions
function Get-StreamContent {
    param(
        [string]$FilePath,
        [string]$StreamName,
        [int]$MaxBytes = 4096
    )
    
    try {
        $streamPath = "${FilePath}:${StreamName}"
        return Get-Content -Path $streamPath -Raw -Encoding Byte -ReadCount 0 -TotalCount $MaxBytes -ErrorAction Stop
    } catch {
        Write-Verbose "Cannot read stream content: $_"
        return $null
    }
}

function Test-ADSExists {
    param([string]$FilePath)
    
    try {
        $streams = Get-Item -Path $FilePath -Stream * -ErrorAction SilentlyContinue
        return ($streams.Count -gt 1)  # More than just primary stream
    } catch {
        return $false
    }
}

# Security validation
function Test-SafePath {
    param([string]$Path)
    
    # Blocklist of sensitive system paths
    $blockedPaths = @(
        'C:\\Windows\\System32\\config',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\Windows\\WinSxS',
        'C:\\Windows\\CSC',
        'C:\\pagefile.sys',
        'C:\\hiberfil.sys',
        'C:\\swapfile.sys'
    )
    
    foreach ($blocked in $blockedPaths) {
        if ($Path -like $blocked) {
            Write-Warning "Blocked sensitive path: $Path"
            return $false
        }
    }
    
    return $true
}

function Get-FileHashSafe {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        return $null
    }
    
    try {
        return Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
    } catch {
        Write-Verbose "Hash calculation failed: $_"
        return $null
    }
}

# Logging utilities
function Write-ADSLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [string]$LogFile
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Host $logEntry -ForegroundColor $(switch ($Level) {
        'ERROR'   { 'Red' }
        'WARNING' { 'Yellow' }
        'ALERT'   { 'Red' }
        'SUCCESS' { 'Green' }
        default   { 'Gray' }
    })
    
    if ($LogFile) {
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
    }
}

# Export module members
Export-ModuleMember -Function *
