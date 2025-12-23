# Identity-Centric Defense - Mitigating Ryuk Ransomware

## Project Overview
This project demonstrates a detection strategy to mitigate the lateral movement of Ryuk Ransomware. Based on the "Ryuk in 5 Hours" report by *The DFIR Report*, this repository focuses on how attackers abuse identity protocols and how to implement proactive and detective controls using Wazuh.

## The Case Study: Ryuk's Identity Abuse
In the analyzed intrusion, the threat actor achieved domain-wide encryption in just 5 hours. The attack's success relied heavily on identity-related failures:
* **Initial Access:** Phishing leading to credential compromise.
* **Privilege Escalation:** Exploitation of Zerologon (CVE-2020-1472) to gain Domain Admin rights.
* **Lateral Movement:** Extensive use of RDP (Remote Desktop Protocol) using compromised administrative accounts.

## IAM Mitigation Strategy
To break the attack chain, the following IAM principles are proposed:
1. **Tiered Administration Model:** Restricting Domain Admin accounts so they can only log into Domain Controllers, preventing credential harvesting on workstations.
2. **MFA Enforcement:** Implementing Multi-Factor Authentication for all RDP sessions, especially for privileged accounts.
3. **Zero Trust Approach:** Implementing "Least Privilege" policies to restrict lateral movement across different network segments.

## Detection Engineering (Wazuh Rules)
This project includes custom Wazuh rules to detect anomalous identity behaviors. 

### Key Detection: Anomalous Admin RDP Logon
We focus on Event ID 4624 with Logon Type 10 (Remote Interactive). The goal is to trigger a high-severity alert when a privileged account accesses a non-IT management station.

*(Upcoming: XML Rule code and Active Response scripts)*

---
## Resources & References
* [The DFIR Report: Ryuk in 5 Hours](https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/)
* [MITRE ATT&CK: Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
