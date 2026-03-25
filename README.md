Purview Configuration Collector
Overview

PowerShell-based collector for extracting Microsoft Purview configuration into structured CSV datasets.

This tool is designed to enable deterministic, evidence-based analysis of Purview environments, without relying on assumptions or inferred logic.

Why this exists

Purview configurations are complex, fragmented, and difficult to analyze consistently.

This tool solves that by:

Extracting configuration as raw evidence
Normalizing output for machine-driven analysis
Enabling repeatable assessments (Architecture Mode / SOC analysis)
What it collects

The script exports the following datasets:

DLP Policies (operator-grade)
DLP Rules (operator-grade)
DLP Rule Conditions
Retention Policies
Retention Rules
Label Policies
Admin Audit Configuration
Design principles
CSV is the source of truth
No transformation or interpretation in the script
Analysis is performed downstream (Copilot / SOC prompts)
Missing values are preserved (no artificial defaults)
Execution

Run from PowerShell 7:

pwsh
cd .\script
.\PurviewDiag.ps1
Output structure

The script generates timestamped output folders:

output/<Tenant>/<Timestamp>/

Each dataset is exported as an independent CSV file.

Logging and traceability

Execution logs are generated per run:

logs/

Includes:

Full transcript
Execution metadata
Dataset counts and warnings
Requirements
PowerShell 7.x
ExchangeOnlineManagement module
Compliance Administrator or Security Administrator role
Usage model

This tool is intended to be used as:

Data collection layer
Input for:
Architecture Mode reporting
SOC-driven analysis
Automated security assessments
Disclaimer

This tool is read-only.

No changes are made to tenant configuration.

Credits

Based on community work and extended for operator-grade Purview analysis.
