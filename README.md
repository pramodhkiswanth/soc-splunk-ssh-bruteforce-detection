# Automated SSH Brute-Force Detection & Active Response  
**Splunk + Linux SOC Lab**

---

## Project Overview

This project demonstrates a complete end-to-end Security Operations Center (SOC) workflow built inside a VirtualBox lab environment using host-only networking.

The lab includes:

- Simulated SSH brute-force attack from a Windows host
- Log ingestion into Splunk SIEM
- Detection using SPL (Search Processing Language)
- Threshold-based alerting
- Automated firewall response
- Validation of attack mitigation

This project demonstrates detection-to-response automation in a controlled lab environment.

---

## Lab Architecture

**Attacker:** Windows Host (192.168.54.1)  
**Target:** Ubuntu VM (192.168.54.3)  
**SIEM:** Splunk  
**Response Mechanism:** UFW / iptables DROP rule insertion  

---

## Data Flow

1. Windows performs repeated SSH login attempts.
2. Ubuntu logs failures via `sshd` (journalctl).
3. Splunk ingests logs into `index=os`.
4. SPL detects >= 5 failures from the same source IP.
5. Alert triggers per result.
6. Script executes and inserts firewall DROP rule.
7. Further SSH attempts are blocked.

---

## Detection Logic (SPL)

```spl
index=os ("Failed password" OR "authentication failure" OR "Invalid user")
| rex field=_raw "(?i)from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| search src_ip!="127.0.0.1"
| stats count as failures by src_ip
| where failures >= 5
```

### Explanation

- Extracts attacker IP using regex.
- Groups authentication failures by source IP.
- Triggers when threshold (>= 5) is exceeded.
- Excludes localhost testing.

---

## Alert Configuration

### Trigger Settings

- Trigger when: **Number of Results > 0**
- Trigger frequency: **For each result**
- Throttle: **Enabled**
- Suppress field: `src_ip`
- Suppress duration: **10 minutes**

### Trigger Actions

- Log Event (writes alert evidence to Splunk)
- Run Script (`alert_block_ip.sh`)

---

## Automated Response

The alert executes:

```
alert_block_ip.sh
```

The script:

- Extracts attacker IP
- Parses alert results
- Calls blocking logic
- Inserts DROP rule into `ufw-user-input`
- Logs action to `/var/log/alert_block_ip.log`

---

## Validation Steps (Evidence)

### 1. Attack Simulation  
`screenshots/01_attack_windows_ssh_failures.png`

### 2. Ubuntu SSH Logs Showing Attacker IP  
`screenshots/02_ubuntu_journalctl_ssh_failures.png`

### 3. Logs Visible in Splunk  
`screenshots/03_splunk_raw_ssh_events.png`

### 4. Detection Results (Grouped by src_ip)  
`screenshots/04_splunk_detection_results.png`

### 5. Alert Trigger Actions Configuration  
`screenshots/05_alert_trigger_actions.png`

### 6. Alert Trigger Conditions  
`screenshots/06_alert_trigger_conditions.png`

### 7. Alert Fired Event Logged in Splunk  
`screenshots/07_alert_fired_logged_event.png`

### 8. Script Execution Log (IP extracted and blocked)  
`screenshots/08_alert_script_execution_log.png`

### 9. Firewall DROP Rule Inserted  
`screenshots/09_firewall_drop_rule.png`

### 10. Windows Connection Blocked (Test-NetConnection)  
`screenshots/10_windows_ssh_blocked_testnetconnection.png`

### 11. Block Audit Log  
`screenshots/11_block_ip_audit_log.png`

---

## MITRE ATT&CK Mapping

- **T1110 — Brute Force**

---

## Security Impact

This project demonstrates:

- SIEM detection engineering
- Regex field extraction
- Alert tuning (throttling + suppression)
- Scripted response automation
- Firewall rule manipulation
- End-to-end validation

---

## Production Considerations

In a production SOC environment:

- Implement allowlists to prevent self-blocking
- Use temporary bans with expiry logic
- Package scripted response as a custom Splunk alert action
- Add monitoring for script failure
- Log response actions to a dedicated security index
- Integrate with ticketing (ServiceNow / Jira)

---

## Author

**Pramodhkiswath**  
SOC / Cybersecurity Lab Project
