PT PROJECT- script 

Bash automation for network reconnaissance and weak-password testing . 


🔍 Overview
A compact, practical script that automates TCP/UDP discovery, service versioning, targeted NSE vuln scans, SearchSploit lookups and weak-credential bruteforce (SSH / RDP / FTP / Telnet). Designed for lab/learning on Kali Linux. 

🔧 Features

Interactive: prompts for target (IP/CIDR) and output directory (validates input). 

Two modes: BASIC (fast TCP + targeted UDP + weak creds) and FULL (BASIC + NSE vulners + SearchSploit). 

Masscan for UDP discovery (rate-limited), Nmap for TCP/UDP service/version detection. 

Weak-credential checks: default lists + optional user password list; uses Medusa / Hydra / nmap telnet-brute. 

Normalized summary output: open_services.txt (PROTOCOL HOST PORT SERVICE VERSION). 

Interactive grep search across results and optional ZIP export. 

📁 Project structure

PT-PROJECT.sh — main script. 

output/ (user-created) — stores BASIC_SCAN/, FULL_SCAN/, open_services.txt, brute results, NSE outputs, searchsploit_results. 

$SCRIPT_DIR/* — auto-created helper files: users.txt, passwords.txt, weak_passwords.lst. 

PT PROJECT

⚙️ Requirements (Kali Linux recommended)

nmap, masscan, hydra, medusa, exploitdb (searchsploit), zip, wget

sudo for package install / masscan where required
(The script can attempt to install missing packages if run with sudo.) 

PT PROJECT

🚀 Quick start

Place the script in a Kali machine and make executable:
chmod +x PT-PROJECT.sh

Run the script:
./PT-PROJECT.sh
(The script will prompt for target IP/CIDR and the output directory name, then ask to choose B = BASIC or F = FULL.) 

💡 Example session (interactive)

Enter target: 192.168.1.0/24

Output dir: SCAN_RESULTS

Choose: B (BASIC) or F (FULL)

After completion use the interactive search prompt or opt to archive results as SCAN_RESULTS.zip. 

PT PROJECT

📝 Notes & best practices

Use only on systems/networks you are authorized to test. This tool performs active scanning and brute-force attempts.

For large scopes or production networks adjust masscan rate and nmap timing (-T) to avoid noise/disruption. 

PT PROJECT

The script creates default username/password lists locally; you can replace them with your curated lists before running. 

PT PROJECT
