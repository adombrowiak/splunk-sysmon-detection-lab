# Splunk + Sysmon Detection Lab

## Overview
This lab demonstrates detection engineering techniques using Sysmon telemetry ingested into Splunk.

The goal is to simulate common attacker behaviors and build detections based on process execution, command-line activity, and parent-child relationships.

## Environment
- Windows 11 VM (endpoint)
- Ubuntu VM (Splunk server)
- Splunk Enterprise
- Sysmon with custom configuration
- Splunk Universal Forwarder

## Data Source
- Microsoft-Windows-Sysmon/Operational (Event ID 1 - Process Creation)

## Techniques Covered
- T1059.001 - PowerShell
- T1218 - Signed Binary Proxy Execution (rundll32)
- Process injection patterns (basic observation)

## Key Skills Demonstrated
- Parsing raw XML logs in Splunk
- Field extraction using regex (rex)
- Process and command-line analysis
- Parent-child process relationships
- Detection logic development

## Example Detections
- Suspicious PowerShell flags (-nop, hidden)
- Encoded PowerShell execution
- rundll32 execution tracking

## Screenshots
### 1. Data Ingestion
![Data ingestion](./screenshots/01_data_ingestion.png)
Sysmon telemetry successfully ingested into Splunk via the Universal Forwarder from a Windows endpoint.

### 2. Raw Sysmon Event (Event ID 1)
![raw_event](./screenshots/02_raw_event.png)
Expanded Sysmon Event ID 1 (Process Creation) in raw XML format, validating event structure and field availability for detection development.

### 3. Field Extraction (Process + Command Line)
![field_extraction](./screenshots/03_field_extraction.png)
Extracted process image and command-line arguments from raw Sysmon XML logs using regex (rex), enabling structured analysis and detection development.

### 4. Detection Logic (PowerShell Activity)
![detection_logic](./screenshots/04_detection_logic.png)
Aggregated Sysmon process creation events to identify PowerShell execution frequency, demonstrating detection-focused analysis using field extraction and statistical grouping.

### 5. Detection Logic (PowerShell Execution Patterns)
![detection_logic](./screenshots/05_detection_logic.png)
This query identifies PowerShell execution activity and aggregates results by both process image and command-line arguments.
By grouping on `cmdline`, this step exposes variations in how PowerShell is executed, enabling visibility into different execution patterns (e.g., standard execution vs. scripted or parameterized usage).
This is critical for detection engineering, as adversaries often modify command-line arguments to evade simple detections.

## Author
Aaron

Cybersecurity professional with 20+ years of experience in digital forensics, incident response, and cybersecurity operations. Holds a Master’s degree in Cybersecurity Technology and CompTIA CySA+. Focused on detection engineering, threat hunting, and SOC workflows.
