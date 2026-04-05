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
Sysmon telemetry successfully ingested into Splunk via the Universal Forwarder from a Windows endpoint.
![Data ingestion](./screenshots/01_data_ingestion.png)

### 2. Raw Sysmon Event (Event ID 1)
Expanded Sysmon Event ID 1 (Process Creation) in raw XML format, validating event structure and field availability for detection development.
![raw_event](./screenshots/02_raw_event.png)

### 3. Field Extraction (Process + Command Line)
Extracted process image and command-line arguments from raw Sysmon XML logs using regex (rex), enabling structured analysis and detection development.
![field_extraction](./screenshots/03_field_extraction.png)

### 4. Detection Logic (PowerShell Activity)
Aggregated Sysmon process creation events to identify PowerShell execution frequency, demonstrating detection-focused analysis using field extraction and statistical grouping.
![detection_logic](./screenshots/04_detection_logic.png)

## Author
Aaron

Cybersecurity professional with 20+ years of experience in digital forensics, incident response, and cybersecurity operations. Holds a Master’s degree in Cybersecurity Technology and CompTIA CySA+. Focused on detection engineering, threat hunting, and SOC workflows.
