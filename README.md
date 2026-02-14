TRS4R3N SOC Monitor v3.0

TRS4R3N SOC Monitor v3.0 is a cross-platform SOC simulation tool that performs log analysis on Windows, Linux, and macOS systems, conducts threat classification using basic machine learning logic, and provides real-time system monitoring.

This project is my first machine learning-supported cybersecurity project.

Project Objectives:
- To understand log analysis processes
- To simulate SOC logic
- To detect attacks such as brute-force and privilege escalation
- To perform real-time endpoint monitoring
- To introduce machine learning from a security perspective

The project aims to:

Understand log analysis processes
- Simulate SOC logic
- Detect attacks such as brute-force and privilege escalation
- Perform real-time endpoint monitoring
- Provide an introduction to machine learning from a security perspective. Architectural Structure

The project consists of 5 main layers:

1️. Authorization Control Layer (Windows)
The program automatically checks admin privileges in Windows.
It restarts itself with RunAs if necessary.
It provides access to Security and Sysmon logs.

2️. Log Collection Layer
Windows
- Sysmon Log
- Security Log
- Active Directory Security Log

Linux
- /var/log/auth.log
- /var/log/syslog

macOS
- /var/log/system.log
- /var/log/secure.log

3️. ML Classification Layer
It performs threat classification based on Event ID and log content. Detected Events
Event Classification
4625 Brute-force
4720 User Creation
4725 User Disabled
4672 Admin Privilege Assignment
failed password Brute-force
sudo Privilege Escalation

This version uses rule-based ML simulation.

4️. Network Monitoring
Using psutil:
Active connections
PID
Process Name
Local IP → Remote IP
Connection status
Updated every 5 seconds.

5️. Performance Monitoring
- CPU usage percentage
- RAM usage percentage
- Update every second

<img width="2482" height="1225" alt="1" src="https://github.com/user-attachments/assets/bc8a8cae-835f-4850-9c2c-4a082dcc4abd" />
TRS4R3N SOC Monitor v3.0 Running on Linux Operating System


TRS4R3N SOC Monitor v3.0 Running on Windows Operating System
<img width="2559" height="1263" alt="2" src="https://github.com/user-attachments/assets/a5d2b47d-0e2c-4bd9-9b63-b2be60174d69" />

GUI Structure
The interface consists of 5 main sections:
Panel Content
Left System Logs
Middle AD / User Logs
Right ML Analysis
Top CPU & RAM
Bottom Network Connections

Data Flow
Event Log / Auth Log
↓
Event Parsing
↓
ml_predict()
↓
Threat Classification
↓
ML Analysis Panel

Installation
1️.Python
Minimum: Python 3.9+
Check:
python --version

2️.Required Libraries
Windows:
pip install psutil pandas pywin32

Linux/macOS:
pip install psutil pandas

3️.Sysmon for Windows (Recommended)
Sysmon installed Otherwise:
No problem, Windows Event Security captures logs, but if you still want to install it,
you can download and install it from Microsoft Sysinternals.

Running
TRS4R3Nsocmonitor.py
For Linux:
sudo python3 main.py

Security Perspective
This tool is suitable for:
Blue Team practice
Log analysis training
SOC simulation
Event ID learning
Incident response beginner level.

My goal:
- To learn SOC processes
- To experience the combination of ML + Security
- To become an expert in the Blue Team field

I am open to feedback.
