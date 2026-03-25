Purview Configuration Collector






🚀 Overview

Purview Configuration Collector is a PowerShell-based tool designed to extract Microsoft Purview configuration into structured CSV datasets for evidence-based analysis.

It acts as the data collection layer for security assessments, architecture reviews, and automated analysis workflows.

🧠 Why this matters

Microsoft Purview environments are:

Complex
Distributed across workloads
Difficult to analyze consistently

This tool enables:

Deterministic analysis (no assumptions)
Repeatable assessments
Clean input for automation (Copilot / SOC workflows)
📦 What gets collected
Area	Dataset
DLP	Policies, Rules, Conditions
Retention	Policies and Rules
Information Protection	Label Policies
Audit	Admin Audit Configuration
⚙️ How it works
Purview → PowerShell Extraction → CSV Output → Copilot / SOC Analysis
▶️ Execution

Run from PowerShell 7:

pwsh
cd .\script
.\PurviewDiag.ps1
🗂 Output Structure
output/<Tenant>/<Timestamp>/

Each dataset is exported as an independent CSV file.

🧾 Logging
logs/

Includes:

Full transcript
Execution metadata
Warnings and dataset counts
📋 Requirements
Requirement	Details
PowerShell	7.x
Module	ExchangeOnlineManagement
Roles	Compliance Admin / Security Admin
🧩 Usage Model

This tool is designed to be used as:

Collector layer
Input for:
Architecture Mode reporting
SOC-driven analysis
Automated compliance assessment
🔒 Design Principles
CSV = source of truth
No transformation in the script
No assumptions
Analysis happens downstream
⚠️ Disclaimer

This tool is read-only.

No changes are made to tenant configuration.

👤 Author

Sergio Calva