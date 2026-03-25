Purview Configuration Collector






Overview

Purview Configuration Collector is a PowerShell-based tool that extracts Microsoft Purview configuration into structured CSV datasets for evidence-based analysis.

Why this matters

Microsoft Purview environments are:

Complex
Distributed across workloads
Difficult to analyze consistently

This tool enables:

Deterministic analysis (no assumptions)
Repeatable assessments
Clean input for automation
What gets collected
Area	Data
DLP	Policies, Rules, Conditions
Retention	Policies and Rules
Information Protection	Label Policies
Audit	Admin Audit Configuration
How it works

Purview → PowerShell Extraction → CSV Output → Analysis (Copilot / SOC)

Execution
pwsh
cd .\script
.\PurviewDiag.ps1
Output
output/<Tenant>/<Timestamp>/

Each dataset is exported as an independent CSV file.

Logging
logs/

Includes transcript, metadata, and warnings.

Requirements
Component	Value
PowerShell	7.x
Module	ExchangeOnlineManagement
Roles	Compliance Admin / Security Admin
Design Principles
CSV is the source of truth
No transformation in the script
No assumptions
Analysis happens downstream
Disclaimer

This tool is read-only.
No changes are made to tenant configuration.

Author

Sergio Calva