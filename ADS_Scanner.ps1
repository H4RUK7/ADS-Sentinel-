<#
.SYNOPSIS
    ADS Sentinel - NTFS Alternate Data Streams Scanner
.DESCRIPTION
    Defensive tool for detecting potentially malicious Alternate Data Streams
    on NTFS file systems. Educational use only.
.PARAMETER Path
    Target directory to scan (default: current directory)
.PARAMETER Recurse
    Scan subdirectories recursively
.PARAMETER OutputFormat
    Output format: Console, JSON, CSV (default: Console)
.PARAMETER Threshold
    Size threshold for suspicious streams in MB (default: 1)
.PARAMETER Verbose
    Detailed output
.EXAMPLE
    .\ADS_Scanner.ps1 -Path C:\Users -Recurse -Verbose
.EXAMPLE
    .\ADS_Scanner.ps1 -Path C:\Windows\Temp -OutputFormat JSON -Threshold 5
.NOTES
    Author: ADS Sentinel Team
    License: MIT
    Security: Defensive/educational use only
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Path = ".",
    
    [switch]$Recurse,
    
    [ValidateSet('Console', 'JSON', 'CSV')]
    [string]$OutputFormat = 'Console',
    
    [int]$Threshold = 1,
    
    [string]$OutputFile
)

#region Initialization
Write-Host @"

██████╗ ██████╗ ███████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔══██╗██╔══██╗██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
██║  ██║██████╔╝███████╗    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██║  ██║██╔══██╗╚════██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
██████╔╝██████╔╝███████║    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗██║
╚═════╝ ╚═════╝ ╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝
                                 NTFS Alternate Data Streams Scanner
                                    Version 1.0 | Educational Use
"@ -ForegroundColor Cyan

Write-Host "`n[INFO] Starting ADS Sentinel Scan" -ForegroundColor Green
Write-Host "[INFO] Path: $($Path)" -ForegroundColor Gray
Write-Host "[INFO] Recursive: $($Recurse)" -ForegroundColor Gray
Write-Host "[INFO] Threshold: ${Threshold}MB" -ForegroundColor Gray
Write-Host "[INFO] Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Load utilities
$UtilitiesPath = Join-Path $PSScriptRoot "Utilities.ps1"
if (Test-Path $UtilitiesPath) {
    . $UtilitiesPath
} else {
    Write-Warning "Utilities.ps1 not found. Some features may be limited."
}
#endregion

#region Detection Signatures
$suspiciousExtensions = @('.exe', '.ps1', '.vbs', '.bat', '.cmd', '.js', '.jse', '.vbe', '.wsf', '.wsh', '.scr', '.pif')
$benignStreams = @('Zone.Identifier', 'encryptable', 'SummaryInformation', 'DocumentSummaryInformation', '{$I30', 'OECustomProperty')
$encodingPatterns = @(
    '^[A-Za-z0-9+/=]{20,}$',  # Base64
    '^[0-9A-Fa-f\s]{20,}$',   # Hex
    'powershell.*\-enc',      # PowerShell encoded command
    'frombase64string',
    'invoke\-expression'
)
#endregion

#region Main Scanning Function
function Scan-ADS {
    param(
        [string]$ScanPath,
        [bool]$RecurseScan
    )
    
    $results = @()
    $streamCount = 0
    $suspiciousCount = 0
    
    try {
        # Validate path
        if (-not (Test-Path $ScanPath)) {
            Write-Error "Path not found: $ScanPath"
            return $results
        }
        
        # Get all files
        $files = Get-ChildItem -Path $ScanPath -File -Recurse:$RecurseScan -ErrorAction SilentlyContinue
        
        foreach ($file in $files) {
            try {
                # Get all streams for this file
                $streams = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue
                
                foreach ($stream in $streams) {
                    $streamCount++
                    
                    # Skip primary data stream
                    if ($stream.Stream -eq ':$DATA' -or [string]::IsNullOrEmpty($stream.Stream)) {
                        continue
                    }
                    
                    # Create result object
                    $result = [PSCustomObject]@{
                        Timestamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        ParentFile    = $file.FullName
                        StreamName    = $stream.Stream.TrimStart(':')
                        StreamType    = $stream.StreamType
                        StreamLength  = $stream.Length
                        FileSize      = $file.Length
                        FileExtension = $file.Extension.ToLower()
                        LastAccess    = $file.LastAccessTime
                        LastWrite     = $file.LastWriteTime
                        Indicators    = @()
                        RiskScore     = 0
                        Status        = 'Benign'
                        ProcessInfo   = $null
                    }
                    
                    # Apply detection heuristics
                    $result = Apply-Heuristics -Result $result
                    
                    # Check if suspicious
                    if ($result.RiskScore -gt 0) {
                        $suspiciousCount++
                        $result.Status = 'Suspicious'
                        
                        # Try to correlate with processes
                        $result.ProcessInfo = Get-ProcessCorrelation -FilePath $result.ParentFile
                    }
                    
                    $results += $result
                    
                    # Console output for suspicious streams
                    if ($result.Status -eq 'Suspicious' -and $OutputFormat -eq 'Console') {
                        Write-Host "`n[ALERT] Suspicious Stream Detected" -ForegroundColor Red
                        Write-Host "----------------------------------" -ForegroundColor DarkRed
                        Write-Host "File: $($result.ParentFile)" -ForegroundColor Yellow
                        Write-Host "Stream: :$($result.StreamName)" -ForegroundColor Yellow
                        Write-Host "Size: $(Format-Size $result.StreamLength)" -ForegroundColor Yellow
                        Write-Host "Risk Score: $($result.RiskScore)/100" -ForegroundColor Yellow
                        Write-Host "Indicators: $($result.Indicators -join ', ')" -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-Verbose "Error processing $($file.FullName): $_"
            }
        }
        
    } catch {
        Write-Error "Scan error: $_"
    }
    
    Write-Host "`n[INFO] Scan Complete" -ForegroundColor Green
    Write-Host "[INFO] Total streams scanned: $streamCount" -ForegroundColor Gray
    Write-Host "[INFO] Suspicious streams: $suspiciousCount" -ForegroundColor $(if ($suspiciousCount -gt 0) {'Red'} else {'Green'})
    
    return $results
}
#endregion

#region Heuristic Functions
function Apply-Heuristics {
    param([PSCustomObject]$Result)
    
    $riskScore = 0
    $indicators = @()
    
    # 1. Check for suspicious extensions in stream name
    foreach ($ext in $suspiciousExtensions) {
        if ($Result.StreamName -like "*$ext") {
            $riskScore += 30
            $indicators += "Executable extension: $ext"
            break
        }
    }
    
    # 2. Check for large streams
    $thresholdBytes = $Threshold * 1MB
    if ($Result.StreamLength -gt $thresholdBytes) {
        $riskScore += 25
        $sizeMB = [math]::Round($Result.StreamLength / 1MB, 2)
        $indicators += "Large stream size: ${sizeMB}MB"
    }
    
    # 3. Check for benign streams (reduce risk)
    if ($benignStreams -contains $Result.StreamName) {
        $riskScore = 0
        $indicators = @('Known benign stream')
        return $Result
    }
    
    # 4. Check stream content for encoding patterns
    try {
        $streamPath = "$($Result.ParentFile):$($Result.StreamName)"
        $content = Get-Content -Path $streamPath -Raw -ErrorAction SilentlyContinue -First 1024
        
        if ($content) {
            foreach ($pattern in $encodingPatterns) {
                if ($content -match $pattern) {
                    $riskScore += 35
                    $indicators += "Encoded/obfuscated content detected"
                    break
                }
            }
        }
    } catch {
        # Cannot read stream content
        $riskScore += 10
        $indicators += "Stream unreadable (may be locked)"
    }
    
    # 5. Check sensitive locations
    $sensitivePaths = @(
        'C:\\Windows\\System32',
        'C:\\Windows\\SysWOW64',
        'C:\\ProgramData',
        'C:\\Users\\*\\AppData',
        'C:\\Windows\\Temp'
    )
    
    foreach ($sensitivePath in $sensitivePaths) {
        if ($Result.ParentFile -like $sensitivePath) {
            $riskScore += 20
            $indicators += "Located in sensitive path"
            break
        }
    }
    
    # Cap risk score
    $riskScore = [math]::Min($riskScore, 100)
    
    $Result.RiskScore = $riskScore
    $Result.Indicators = $indicators
    
    return $Result
}

function Get-ProcessCorrelation {
    param([string]$FilePath)
    
    try {
        # Use handle.exe if available (SysInternals)
        $handlePath = "$env:SystemRoot\System32\handle.exe"
        if (Test-Path $handlePath) {
            $handles = & $handlePath -p * -a -nobanner 2>$null | Where-Object { $_ -like "*$([System.IO.Path]::GetFileName($FilePath))*" }
            if ($handles) {
                return @{
                    HasHandles = $true
                    Tool = 'handle.exe'
                    Info = $handles
                }
            }
        }
        
        # Alternative: Check running PowerShell processes for file references
        $psProcesses = Get-Process -Name powershell* -ErrorAction SilentlyContinue
        foreach ($proc in $psProcesses) {
            try {
                $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
                if ($cmdLine -like "*$FilePath*") {
                    return @{
                        HasHandles = $true
                        ProcessId = $proc.Id
                        ProcessName = $proc.ProcessName
                        CommandLine = $cmdLine
                    }
                }
            } catch {
                # Cannot access process
            }
        }
        
    } catch {
        Write-Verbose "Process correlation failed: $_"
    }
    
    return @{
        HasHandles = $false
        Info = 'No correlation found'
    }
}

function Format-Size {
    param([long]$Bytes)
    
    if ($Bytes -ge 1GB) {
        return "{0:N2} GB" -f ($Bytes / 1GB)
    } elseif ($Bytes -ge 1MB) {
        return "{0:N2} MB" -f ($Bytes / 1MB)
    } elseif ($Bytes -ge 1KB) {
        return "{0:N2} KB" -f ($Bytes / 1KB)
    } else {
        return "$Bytes bytes"
    }
}
#endregion

#region Output Functions
function Export-Results {
    param([array]$Results, [string]$Format, [string]$File)
    
    switch ($Format) {
        'JSON' {
            $json = $Results | ConvertTo-Json -Depth 3
            if ($File) {
                $json | Out-File -FilePath $File -Encoding UTF8
                Write-Host "[INFO] Results saved to: $File" -ForegroundColor Green
            } else {
                return $json
            }
        }
        'CSV' {
            $csv = $Results | Export-Csv -Path $File -NoTypeInformation -Encoding UTF8
            Write-Host "[INFO] Results saved to: $File" -ForegroundColor Green
        }
        default {
            # Console output already handled during scan
        }
    }
}
#endregion

#region Main Execution
# Create results directory if needed
if ($OutputFile -and -not (Test-Path (Split-Path $OutputFile -Parent))) {
    New-Item -ItemType Directory -Path (Split-Path $OutputFile -Parent) -Force | Out-Null
}

# Perform scan
$scanResults = Scan-ADS -ScanPath $Path -RecurseScan $Recurse

# Export results if requested
if ($OutputFormat -in @('JSON', 'CSV')) {
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $OutputFile = Join-Path $PSScriptRoot "..\logs\ads_scan_${timestamp}.$($OutputFormat.ToLower())"
    }
    
    Export-Results -Results $scanResults -Format $OutputFormat -File $OutputFile
}

# Summary
if ($scanResults.Count -gt 0 -and $OutputFormat -eq 'Console') {
    Write-Host "`n" + "="*50 -ForegroundColor Cyan
    Write-Host "SCAN SUMMARY" -ForegroundColor Cyan
    Write-Host "="*50 -ForegroundColor Cyan
    
    $suspicious = $scanResults | Where-Object { $_.Status -eq 'Suspicious' }
    
    if ($suspicious.Count -gt 0) {
        Write-Host "`n[!] SUSPICIOUS STREAMS FOUND ($($suspicious.Count))" -ForegroundColor Red
        
        foreach ($stream in $suspicious | Sort-Object RiskScore -Descending | Select-Object -First 5) {
            Write-Host "`n  File: $($stream.ParentFile)" -ForegroundColor Yellow
            Write-Host "  Stream: :$($stream.StreamName)" -ForegroundColor Yellow
            Write-Host "  Risk: $($stream.RiskScore)/100" -ForegroundColor $(if ($stream.RiskScore -gt 50) {'Red'} else {'Yellow'})
            Write-Host "  Indicators: $($stream.Indicators -join ', ')" -ForegroundColor Gray
        }
        
        Write-Host "`n[ACTION] Review suspicious streams above. Use Response_Module.ps1 for safe quarantine." -ForegroundColor Red
        
    } else {
        Write-Host "`n[✓] No suspicious streams detected" -ForegroundColor Green
    }
    
    Write-Host "`n[INFO] Scan completed at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
}

# Return results for pipeline
return $scanResults
#endregion
