
# 🔍 ADS Sentinel - NTFS Alternate Data Streams Monitor

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)

A defensive security tool for detecting, monitoring, and responding to potentially malicious NTFS Alternate Data Streams (ADS) activity. Designed for cybersecurity education, home labs, and defensive research.

## ⚠️ SECURITY DISCLAIMER
**This tool is for DEFENSIVE and EDUCATIONAL purposes only.** Use only on systems you own or have explicit permission to test. Never use for unauthorized security testing.

## ✨ Features
- **Comprehensive ADS Detection**: Enumerate all NTFS alternate data streams
- **Heuristic Analysis**: Identify suspicious streams using multiple indicators
- **Process Correlation**: Link ADS activity to running processes
- **Safe Response**: Quarantine and alert without destructive actions
- **Detailed Logging**: JSON and CSV output for forensic analysis
- **Educational Focus**: Clear documentation of ADS mechanics

## 🚀 Quick Start
```powershell
# Clone repository
git clone https://github.com/yourusername/ADS-Sentinel.git
cd ADS-Sentinel

# Run basic scan
.\src\ADS_Scanner.ps1 -Path C:\Users -Recurse
