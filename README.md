# Suricata IDS/IPS + Microsoft Sentinel Integration Lab

**Platform:** Microsoft Azure | **Tools:** Suricata, Microsoft Sentinel, Kali Linux, Nmap, Hydra, KQL

---

## What This Lab Is About

This lab simulates a real SOC detection pipeline - from deploying a network intrusion detection system on a cloud VM, to writing custom detection rules, generating actual attacks, and investigating the resulting incidents in a SIEM.

Everything here was done from scratch on Azure free credits. No shortcuts, no pre-built templates. The VM got frozen twice during setup and had to be rebuilt - which honestly taught more than if everything had worked the first time.

---

## Lab Environment

| Component | Details |
|---|---|
| Victim / Sensor | Ubuntu 22.04 Azure VM (suricata-vm) |
| Attacker | Kali Linux (VirtualBox on local machine) |
| SIEM | Microsoft Sentinel (soc-lab-logs workspace) |
| IDS Engine | Suricata 7.0.3 |
| Ruleset | Emerging Threats Free Ruleset |
| Log Forwarding | Syslog via Azure Monitor Agent (facility: local5) |

---

## Objectives

- Deploy and configure Suricata IDS on an Azure Ubuntu VM
- Write a custom Suricata detection rule from scratch
- Forward Suricata alerts to Microsoft Sentinel via syslog
- Simulate real attacks from Kali Linux
- Build Sentinel analytics rules with MITRE ATT&CK mapping
- Investigate generated incidents in Sentinel

---

## What I Did - Step by Step

### 1. Deployed Ubuntu VM on Azure

Created Ubuntu Server 22.04 LTS on Azure using Spot pricing to save credits. Configured NSG inbound rules to allow SSH (22), HTTP (80), and HTTPS (443) for attack simulation.

### 2. Installed and Configured Suricata

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install suricata -y
sudo suricata-update
sudo systemctl enable suricata
sudo systemctl start suricata
```

Updated `/etc/suricata/suricata.yaml`:
- Set HOME_NET to cover the VM's private IP range
- Enabled syslog output on `facility: local5` to ship alerts to Sentinel
- Added `local.rules` to the rule-files list

### 3. Wrote a Custom Detection Rule

Created `/var/lib/suricata/rules/local.rules` with this rule:

```
alert http any any -> $HOME_NET any (msg:"CUSTOM RULE - LFI attempt etc passwd"; content:"/etc/passwd"; http_uri; classtype:web-application-attack; sid:9000001; rev:1;)
```

This rule detects Local File Inclusion attempts targeting `/etc/passwd` via HTTP URI. SID 9000001 is a custom identifier used to query this specific rule in Sentinel.

### 4. Connected Suricata VM to Microsoft Sentinel

- Created Log Analytics Workspace (soc-lab-logs) in honeypot-rg resource group
- Installed Azure Monitor Agent on the Ubuntu VM via Azure Portal
- Created Data Collection Rule (DCR-Linux-Syslog) for Syslog ingestion
- Confirmed Suricata alerts flowing into Sentinel:

```kql
Syslog
| where ProcessName == "suricata"
| where Facility == "local5"
| take 20
```

### 5. Attack Simulation from Kali Linux

Ran three attack types targeting the Azure VM's public IP:

**Port Scan - Nmap**
```bash
sudo nmap -sS -A -T4 -Pn 4.240.91.2
```

**SSH Brute Force - Hydra**
```bash
hydra -l azureuser -P passwords.txt ssh://4.240.91.2 -t 4 -V
```

**Web Application Attacks - curl LFI**
```bash
curl "http://4.240.91.2/etc/passwd"
curl "http://4.240.91.2/etc/shadow"
curl "http://4.240.91.2/?id=1' OR '1'='1"
```

### 6. Built Sentinel Analytics Rules

Created 3 scheduled analytics rules in Sentinel with MITRE ATT&CK mapping:

**Rule 1 - SSH Brute Force Detection**
- Severity: Medium
- Tactic: Credential Access | Technique: T1110
- Fires when SSH scan alerts are detected from a source IP

**Rule 2 - Local File Inclusion Attempt**
- Severity: High
- Tactic: Initial Access | Technique: T1190
- Fires on WEB_SERVER /etc/passwd or /etc/shadow detections

**Rule 3 - Custom Rule Trigger (SID 9000001)**
- Severity: High
- Tactics: Discovery + Initial Access | Techniques: T1083, T1190
- Fires specifically when my custom-written rule detects LFI

### 7. Investigated Incidents in Sentinel

Incidents generated automatically from analytics rules. Investigation graph showed multiple source IPs connecting to the suricata-vm entity. The alert name format was set dynamically to show the actual attacker IP: `Suricata SSH Scan from {{SrcIP}}`.

---

## KQL Queries Used

**All Suricata alerts in last 3 hours, grouped by type:**
```kql
Syslog
| where ProcessName == "suricata"
| where Facility == "local5"
| where TimeGenerated > ago(3h)
| extend AlertName = extract(@"\] (.+?) \[Classification", 1, SyslogMessage)
| summarize count() by AlertName
| order by count_ desc
```

**SSH scan with source IP extraction:**
```kql
Syslog
| where ProcessName == "suricata"
| where Facility == "local5"
| where SyslogMessage contains "SSH Scan"
| extend SrcIP = extract(@"\{TCP\} ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", 1, SyslogMessage)
| extend DstIP = extract(@"-> ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", 1, SyslogMessage)
| where isnotempty(SrcIP)
| project TimeGenerated, SrcIP, DstIP, SyslogMessage
```

**Custom rule SID 9000001 detections:**
```kql
Syslog
| where ProcessName == "suricata"
| where SyslogMessage contains "9000001"
| project TimeGenerated, SyslogMessage
```

**Alert volume timeline:**
```kql
Syslog
| where ProcessName == "suricata"
| where Facility == "local5"
| summarize AlertCount = count() by bin(TimeGenerated, 5m)
| render timechart
```

---

## Alerts Detected in Sentinel

| Alert Name | Count |
|---|---|
| ET SCAN Potential SSH Scan | 29 |
| ET INFO SSH-2.0-Go version string | 27 |
| ET DROP Dshield Block Listed Source group 1 | 13 |
| ET DROP Spamhaus DROP Listed Traffic group 7 | 9 |
| SURICATA TCPv4 invalid checksum | 7 |
| ET DROP Spamhaus DROP Listed Traffic group 15 | 7 |
| ET WEB_SERVER /etc/passwd Detected in URI | 3 |
| ET COMPROMISED Known Compromised Host Traffic | 3 |
| ET CINS Active Threat Intelligence | 2 |
| ET HUNTING ZIP file exfiltration over raw TCP | 2 |
| CUSTOM RULE - LFI attempt etc passwd (SID 9000001) | 2 |

Note: Several alerts came from real internet threat actors actively scanning the honeypot VM, not just the simulated attacks. This is expected for a publicly exposed Azure VM.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Source |
|---|---|---|
| T1595 | Active Scanning | Nmap port scan |
| T1110 | Brute Force | Hydra SSH brute force |
| T1190 | Exploit Public-Facing Application | curl LFI attempts |
| T1083 | File and Directory Discovery | /etc/passwd URI access |

---

## Screenshots

### Suricata Running and Generating Alerts

<img width="1904" height="1030" alt="Suricata status" src="https://github.com/user-attachments/assets/2b6c0b78-27a3-46d5-99de-ea3196d663b9" />

### Custom Rule SID 9000001 Firing in fast.log

<img width="1904" height="1030" alt="suricata log showing custom rule firing" src="https://github.com/user-attachments/assets/5abb13d1-9b2a-4a37-9a92-c1504cdf274a" />

### Attack Simulation from Kali Linux

<img width="1912" height="1048" alt="Kali attack generation of suricata" src="https://github.com/user-attachments/assets/0f4b8a8a-2559-4a85-9801-af04987f4069" />

### Suricata Alert Summary in Sentinel (KQL)

 <img width="1920" height="1080" alt="suricata logs summary " src="https://github.com/user-attachments/assets/508a421c-1aad-447f-9cf4-93fdac112875" />

### Analytics Rules with MITRE ATT&CK Mapping

<img width="1920" height="1080" alt="created Analytic rules" src="https://github.com/user-attachments/assets/08a18ac7-16ad-40c7-bb7a-0dcdd1d097c0" />

### Incidents Generated in Sentinel

<img width="1920" height="1080" alt="incident fired based on rules" src="https://github.com/user-attachments/assets/8c24ff29-16e8-49ec-bfe6-3479dabf1a97" />

### Investigation Graph - Entity Mapping
<img width="1920" height="1080" alt="investigation mapping" src="https://github.com/user-attachments/assets/afb106ae-8f2f-48d0-8a47-d0e6c59560f2" />

---

## Key Takeaways

Working through actual errors - frozen VMs, wrong config file paths, YAML indentation issues breaking Suricata on restart - taught more than a clean tutorial run would have. A few things that actually clicked:

Suricata reads traffic at Layer 7. A firewall like pfSense controls access at Layer 3/4. They solve different problems and work together, not instead of each other.

IDS mode watches and alerts. IPS mode drops packets. Starting with IDS is safer because false positives in IPS mode directly disrupt business traffic.

Writing a rule means understanding packet structure - protocol, direction, content match, classification, and SID. SID 9000001 fired correctly on the first real test.

Sentinel analytics rules are what convert raw logs into actionable incidents. Without them, logs just sit in a table doing nothing.

Real internet threat actors were hitting the VM within minutes of it going public. The ET DROP and ET CINS alerts were not from my simulated attacks - they were real unsolicited scanning activity. That alone made the lab feel less like practice and more like actual monitoring.

---

## Tools and Technologies

Suricata 7.0.3, Microsoft Sentinel, Azure Monitor Agent, Log Analytics Workspace, KQL, Kali Linux, Nmap 7.98, Hydra 9.6, nginx, Azure NSG, Emerging Threats free ruleset, syslog facility local5

---
