Purview Configuration Collector
<<<<<<< HEAD






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
=======
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
>>>>>>> 8d01e76ff24e08bc43e3e5cafda7749bf79a289c

Run from PowerShell 7:

pwsh
cd .\script
.\PurviewDiag.ps1
<<<<<<< HEAD
🗂 Output Structure
=======
Output structure

The script generates timestamped output folders:

>>>>>>> 8d01e76ff24e08bc43e3e5cafda7749bf79a289c
output/<Tenant>/<Timestamp>/

Each dataset is exported as an independent CSV file.

<<<<<<< HEAD
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
=======
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
>>>>>>> 8d01e76ff24e08bc43e3e5cafda7749bf79a289c

No changes are made to tenant configuration.

<<<<<<< HEAD
👤 Author

Sergio Calva
=======
Based on community work and extended for operator-grade Purview analysis.
>>>>>>> 8d01e76ff24e08bc43e3e5cafda7749bf79a289c
