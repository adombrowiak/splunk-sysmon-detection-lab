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

![Data ingestion](<img width="1531" height="715" alt="01_data_ingestion" src="https://github.com/user-attachments/assets/c6d02a17-2093-4dce-bd87-257a0f947cff" />)

### Data Ingestion

Sysmon telemetry successfully ingested into Splunk from a Windows endpoint using the Universal Forwarder.

## Author
Aaron

Cybersecurity professional with 20+ years of experience in digital forensics, incident response, and cybersecurity operations. Holds a Master’s degree in Cybersecurity Technology and CompTIA CySA+. Focused on detection engineering, threat hunting, and SOC workflows.
