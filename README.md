Purview Assessment Toolkit (CSV-Based)
Overview

This solution provides a deterministic, evidence-based assessment of Microsoft Purview configurations using CSV exports.

It is composed of:

A PowerShell extraction script
A Copilot-driven analysis model (Architecture Mode + SOC prompts)
Design Principles
CSV files are the single source of truth
No assumptions or inferred logic
Missing values → "Not evidenced in provided sources."
Fully reproducible outputs
What This Script Does

Exports Purview configuration into structured CSV datasets:

DLP Policies (operator-grade)
DLP Rules (operator-grade)
DLP Rule Conditions
Retention Policies
Retention Rules
Label Policies
Admin Audit configuration
Requirements
PowerShell 7.x
ExchangeOnlineManagement module
Compliance Administrator or Security Administrator role
Execution
pwsh
cd .\script
.\PurviewDiag.ps1
Output

The script generates timestamped folders:

output/<Tenant>/<Timestamp>/

Each dataset is aligned with Copilot analysis requirements.

Logging

Execution logs are stored in:

logs/

Includes transcript and run metadata.

Disclaimer

This tool is read-only.
It does not modify any Microsoft 365 configuration.

Credits

Based on community contributions and extended for operator-grade Purview analysis.