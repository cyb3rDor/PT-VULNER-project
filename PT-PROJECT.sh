#!/bin/bash

TARGET=""
OUTPUT_DIR=""

SCRIPT_DIR="$PWD"

BASIC() {
    echo "[*] Running BASIC scan on: $TARGET"
    echo "[i] Output: $OUTPUT_DIR"

    BASIC_DIR="$OUTPUT_DIR/BASIC_SCAN"
    mkdir -p "$BASIC_DIR" 

    # Use lists that live next to the script (absolute) (byGPT)
    WORDLIST="$SCRIPT_DIR/weak_passwords.lst"
    S_PASSLIST="$SCRIPT_DIR/passwords.txt"
    S_USERLIST="$SCRIPT_DIR/users.txt"

    # Make sure they are absolute even if script_dir has symlinks (byGPT)
    [ -f "$S_USERLIST" ] && S_USERLIST="$(readlink -f "$S_USERLIST" 2>/dev/null || echo "$S_USERLIST")"
    [ -f "$S_PASSLIST" ] && S_PASSLIST="$(readlink -f "$S_PASSLIST" 2>/dev/null || echo "$S_PASSLIST")"
    [ -f "$WORDLIST"   ] && WORDLIST="$(readlink -f "$WORDLIST"   2>/dev/null || echo "$WORDLIST")"

    TCP_SCAN_FILE="$BASIC_DIR/tcp_scan.txt"
    UDP_SCAN_FILE="$BASIC_DIR/udp_scan.txt"
    OPEN_SERVICES_FILE="$BASIC_DIR/open_services.txt"

    #1.3.1 Basic: scans the network for TCP and UDP, including the service version and weak passwords
    echo "[*] Nmap Scaning for TCP (-sV, top 1000 ports)..."
    # Redirect Nmap output to /dev/null while saving results to file
    nmap -sV -T4 -Pn -n "$TARGET" -oN "$TCP_SCAN_FILE" >/dev/null 2>&1

    ##Orginize output of nmap - used by GPT
   awk '/Nmap scan report for/ {host=$NF} /\/tcp/ && $2=="open" {p=$1; gsub("/tcp","",p); svc=$3; if (NF>3) {ver=""; for (i=4;i<=NF;i++) ver=ver" "$i; sub(/^ /,"",ver); print "TCP",host,p,svc,ver} else {print "TCP",host,p,svc,"-"}}' "$TCP_SCAN_FILE" >> "$OPEN_SERVICES_FILE"


    # UDP scan in 2 stages: 1. masscan for port reveal. 2. nmap for specific ports.
	echo "[*] masscan UDP discovery..."
    UDP_PORTS_TMP="$BASIC_DIR/udp_ports.tmp"

        # If target is a CIDR, scan UDP only on live hosts from the TCP phase (byGPT)
        if echo "$TARGET" | grep -q '/'; then
            LIVE_HOSTS_FILE="$BASIC_DIR/live_hosts.txt"
            awk '/^Nmap scan report for /{print $NF}' "$TCP_SCAN_FILE" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' > "$LIVE_HOSTS_FILE"

            if [ -s "$LIVE_HOSTS_FILE" ]; then
                echo "[i] UDP discovery on live hosts only: $(wc -l < "$LIVE_HOSTS_FILE") hosts."
                sudo masscan -pU:0-65535 -iL "$LIVE_HOSTS_FILE" --rate 10000 --wait 2 2>/dev/null | awk '/Discovered open port/{print $4}' | cut -d'/' -f1 | sort -n | uniq > "$UDP_PORTS_TMP"
            else
                echo "[i] No live hosts parsed from TCP scan; falling back to full-CIDR UDP."
                sudo masscan -pU:0-65535 "$TARGET" --rate 10000 --wait 2 2>/dev/null | awk '/Discovered open port/{print $4}' | cut -d'/' -f1 | sort -n | uniq > "$UDP_PORTS_TMP"
            fi
        else
            sudo masscan -pU:0-65535 "$TARGET" --rate 10000 --wait 2 2>/dev/null | awk '/Discovered open port/{print $4}' | cut -d'/' -f1 | sort -n | uniq > "$UDP_PORTS_TMP"
        fi

        if [ -s "$UDP_PORTS_TMP" ]; then
            UDP_CSV="$(paste -sd, "$UDP_PORTS_TMP")"
            echo "[*] Nmap UDP (-sU -sV) on: $UDP_CSV"
            # Run UDP Nmap silently (output goes to file)
            nmap -sU -sV -T4 -Pn -n -p "$UDP_CSV" "$TARGET" -oN "$UDP_SCAN_FILE" >/dev/null 2>&1
            ##Orginize output of nmap - used by GPT
            awk '/Nmap scan report for/ {host=$NF} /\/udp/ && $2=="open" {p=$1; gsub("/udp","",p); svc=$3; if (NF>3) {ver=""; for (i=4;i<=NF;i++) ver=ver" "$i; sub(/^ /,"",ver); print "UDP",host,p,svc,ver} else {print "UDP",host,p,svc,"-"}}' "$UDP_SCAN_FILE" >> "$OPEN_SERVICES_FILE"
        else
            echo "[i] No open UDP by masscan."
            : > "$UDP_SCAN_FILE"
        fi
        rm -f "$UDP_PORTS_TMP"

    echo "[+] Open services found and orginized as (PROTOCOL HOST PORT SERVICE VERSION) & saved to $OPEN_SERVICES_FILE"

#2. Weak Credentials
#2.1 Look for weak passwords used in the network for login services.
#2.1.1 Have a built-in password.lst to check for weak passwords.
#2.1.2 Allow the user to supply their own password list.
#2.2 Login services to check include: SSH, RDP, FTP, and TELNET.
WEEK_PASSWORDS() {
    BRUT_FORCE_WEEK_RESULTS="$BASIC_DIR/default_brut_force_week_results.txt"
    echo "[*] Weak-password brute-force (ssh/rdp/ftp/telnet) is in progress"
    echo "[*] You will now get two options. A-Brute-Force ssh/rdp/ftp/telnet by default list or your own list"
    read -p "Please choose t [D/P]. D=DEFAULT, P=YOUR OWN PASSWORD LIST: " S_TYPE
    case $S_TYPE in
        D|d) 
          for service in ssh rdp ftp telnet; do
            if [ "$service" = "rdp" ]; then
                ENTRIES=$(awk 'toupper($1)=="TCP" && tolower($4) ~ /^(ms-wbt-server|rdp)$/' "$OPEN_SERVICES_FILE")
            else
                ENTRIES=$(awk -v svc="$service" 'toupper($1)=="TCP" && tolower($4)==svc' "$OPEN_SERVICES_FILE")
            fi
            [ -z "$ENTRIES" ] && { echo "[i] No open $service. Skipping."; continue; }

            # Per-host brute-force by service
            echo "$ENTRIES" | while read -r line; do
                proto=$(echo "$line" | awk '{print $1}')
                host=$(echo  "$line" | awk '{print $2}')
                port=$(echo  "$line" | awk '{print $3}')
                svc=$(echo   "$line" | awk '{print tolower($4)}')

                case "$svc" in
                    rdp|ms-wbt-server)
                        echo "[*] Medusa rdp on $host:$port ..." | tee -a "$BRUT_FORCE_WEEK_RESULTS"
                        # Suppress Medusa output; results are written to file
                        medusa -h "$host" -n "$port" -U "$S_USERLIST" -P "$S_PASSLIST" -M rdp -O "$BASIC_DIR/default_medusa_rdp_${host}_${port}.txt" >/dev/null 2>&1
						
						# Normalize Medusa output to Hydra-like line (login/password) #by GPT
						if [ -f "$BASIC_DIR/default_medusa_rdp_${host}_${port}.txt" ]; then
							grep -i "ACCOUNT FOUND" "$BASIC_DIR/default_medusa_rdp_${host}_${port}.txt" | sed -E 's/.*Host:[ ]*([^ ]+)[ ]*User:[ ]*([^ ]+)[ ]*Password:[ ]*([^ ]+).*/host: \1  login: \2  password: \3/' | sed "s/^/[${port}][${svc}] /" >> "$BRUT_FORCE_WEEK_RESULTS"
						fi

                        ;;
                    ssh)
                        echo "[*] Medusa ssh on $host:$port ..." | tee -a "$BRUT_FORCE_WEEK_RESULTS"
                        # Suppress Medusa SSH output
                        medusa -h "$host" -n "$port" -U "$S_USERLIST" -P "$S_PASSLIST" -M ssh -t 16 -O "$BASIC_DIR/default_medusa_ssh_${host}_${port}.txt" >/dev/null 2>&1
   						# Normalize Medusa output to Hydra-like line (login/password) #by GPT
                        if [ -f "$BASIC_DIR/default_medusa_ssh_${host}_${port}.txt" ]; then
							grep -i "ACCOUNT FOUND" "$BASIC_DIR/default_medusa_ssh_${host}_${port}.txt" | sed -E 's/.*Host:[ ]*([^ ]+)[ ]*User:[ ]*([^ ]+)[ ]*Password:[ ]*([^ ]+).*/host: \1  login: \2  password: \3/' | sed "s/^/[${port}][${svc}] /" >> "$BRUT_FORCE_WEEK_RESULTS"
						fi

                        ;;
                    ftp)
                        echo "[*] Hydra ftp on $host:$port ..." | tee -a "$BRUT_FORCE_WEEK_RESULTS"
                        # Run Hydra quietly; results go to file
                        hydra -q -C "$WORDLIST" -s "$port" "$host" ftp -o "$BASIC_DIR/default_hydra_ftp_${host}_${port}.txt" >/dev/null 2>&1
                        [ -f "$BASIC_DIR/default_hydra_ftp_${host}_${port}.txt" ] && cat "$BASIC_DIR/default_hydra_ftp_${host}_${port}.txt" >> "$BRUT_FORCE_WEEK_RESULTS"
                        ;;
                    telnet)
                        echo "[*] Hydra telnet on $host:$port ..." | tee -a "$BRUT_FORCE_WEEK_RESULTS"
                        # Suppress Hydra telnet output
                        hydra -q -C "$WORDLIST" -s "$port" "$host" telnet -o "$BASIC_DIR/default_hydra_telnet_${host}_${port}.txt" >/dev/null 2>&1
						[ -f "$BASIC_DIR/default_hydra_telnet_${host}_${port}.txt" ] && cat "$BASIC_DIR/default_hydra_telnet_${host}_${port}.txt" >> "$BRUT_FORCE_WEEK_RESULTS"
                        ;;
                esac
            done
        done
        
    echo "[+] Default brute-force results:"
    if grep -q -E "login:|password:" "$BRUT_FORCE_WEEK_RESULTS"; then
        grep -E "login:|password:" "$BRUT_FORCE_WEEK_RESULTS" | sed 's/^/[✓] /'
    else
        echo "[i] No weak creds found."
    fi

    echo "[✓] Basic scan with weeak default cradentials bruteforce completed."
         ;;
        P|p) 
        
        CUSTOM_BRUT_FORCE_WEEK_RESULTS="$BASIC_DIR/custom_brut_force_week_results.txt"
        read -p "Enter path to your password list (leave empty to skip): " pass_path
        if [ -n "$pass_path" ] && [ -f "$pass_path" ]; then
            pass_path="$(readlink -f "$pass_path" 2>/dev/null || echo "$PWD/$pass_path")" ##symbolic link tined by GPT
            S_USERLIST="$SCRIPT_DIR/users.txt"
            echo "[*] Extended brute-force using users.txt and your password list."
            for service in ssh rdp ftp telnet; do
                if [ "$service" = "rdp" ]; then
                    ENTRIES=$(awk 'toupper($1)=="TCP" && tolower($4) ~ /^(ms-wbt-server|rdp)$/' "$BASIC_DIR/open_services.txt")
                else
                    ENTRIES=$(awk -v svc="$service" 'toupper($1)=="TCP" && tolower($4)==svc' "$BASIC_DIR/open_services.txt")
                fi
                [ -z "$ENTRIES" ] && continue

                echo "$ENTRIES" | while read -r line; do
                    host=$(echo  "$line" | awk '{print $2}')
                    port=$(echo  "$line" | awk '{print $3}')
                    svc=$(echo   "$line" | awk '{print tolower($4)}')

			case "$svc" in
				rdp|ms-wbt-server)
					echo "[*] Medusa (custom) rdp on $host:$port ..." | tee -a "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"
					# Suppress Medusa custom rdp output
					medusa -h "$host" -n "$port" -U "$S_USERLIST" -P "$pass_path" -M rdp -O "$BASIC_DIR/medusa_custom_rdp_${host}_${port}.txt" >/dev/null 2>&1

					# Normalize Medusa output to Hydra-like line (login/password)
					if [ -f "$BASIC_DIR/medusa_custom_rdp_${host}_${port}.txt" ]; then
						grep -i "ACCOUNT FOUND" "$BASIC_DIR/medusa_custom_rdp_${host}_${port}.txt" | sed -E 's/.*Host:[ ]*([^ ]+)[ ]*User:[ ]*([^ ]+)[ ]*Password:[ ]*([^ ]+).*/host: \1  login: \2  password: \3/' | sed "s/^/[${port}][${svc}] /" >> "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"
					fi
					;;
				ssh)
					echo "[*] Medusa (custom) ssh on $host:$port ..." | tee -a "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"
					# Suppress Medusa custom ssh output
					medusa -h "$host" -n "$port" -U "$S_USERLIST" -P "$pass_path" -M ssh -O "$BASIC_DIR/medusa_custom_ssh_${host}_${port}.txt" >/dev/null 2>&1

					# Normalize Medusa output to Hydra-like line (login/password)
					if [ -f "$BASIC_DIR/medusa_custom_ssh_${host}_${port}.txt" ]; then
						grep -i "ACCOUNT FOUND" "$BASIC_DIR/medusa_custom_ssh_${host}_${port}.txt" | sed -E 's/.*Host:[ ]*([^ ]+)[ ]*User:[ ]*([^ ]+)[ ]*Password:[ ]*([^ ]+).*/host: \1  login: \2  password: \3/' | sed "s/^/[${port}][${svc}] /" >> "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"
					fi
					;;
                 ftp)
                     echo "[*] Hydra (custom) ftp on $host:$port ..." | tee -a "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"
                     hydra -q -L "$S_USERLIST" -P "$pass_path" -s "$port" "$host" ftp -o "$BASIC_DIR/hydra_custom_ftp_${host}_${port}.txt" >/dev/null 2>&1
                     [ -f "$BASIC_DIR/hydra_custom_ftp_${host}_${port}.txt" ] && cat "$BASIC_DIR/hydra_custom_ftp_${host}_${port}.txt" >> "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"
                     ;;
                 telnet)
                        echo "[*] Telnet (custom) via NSE telnet-brute on $host:$port ..." | tee -a "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"
                        OUT="$BASIC_DIR/nse_custom_telnet_brute_${host}_${port}.txt"
                        nmap -Pn -n -sT -p "$port" --script telnet-brute --script-args "userdb=$S_USERLIST,passdb=$pass_path,unpwdb.timelimit=0s,brute.firstonly=false" "$host" -oN "$OUT" >/dev/null 2>&1
				    	# Normalize output to Hydra-like line (login/password) #by GPT
					    if [ -f "$OUT" ]; then awk -v h="$host" -v p="$port" 'BEGIN{IGNORECASE=1} /valid credentials/ {if (match($0,/([[:graph:]]+):([[:graph:]]+)/,m)) printf "[%s][telnet] host: %s   login: %s   password: %s\n",p,h,m[1],m[2]}' "$OUT" >> "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"; fi
                        ;;

                    esac
                done
            done
        else
            echo "[i] No valid password list provided. Skipping extended brute-force." | tee -a "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"
        fi

        echo "[+] Extended brute-force summary:"
        if [ -f "$CUSTOM_BRUT_FORCE_WEEK_RESULTS" ]; then
            local _found_creds=false
            if grep -q -E "login:|password:" "$CUSTOM_BRUT_FORCE_WEEK_RESULTS"; then
                grep -E "login:|password:" "$CUSTOM_BRUT_FORCE_WEEK_RESULTS" | sed 's/^/[✓] /'
                _found_creds=true
            fi
            if [ "$_found_creds" = false ]; then
                echo "[i] No credentials found by custom list."
            fi
        else
            echo "[i] No credentials found by custom list."
        fi

    echo "[✓] Basic scan with weeak user cradentials bruteforce completed."
         ;;
        *) WEEK_PASSWORDS   ;;
    esac
}
    WEEK_PASSWORDS

  }
# 1.3.2 Full: include Nmap Scripting Engine (NSE), weak passwords, and vulnerability analysis.
# ===== FULL =====
FULL() {
    echo "[*] Running FULL scan on: $TARGET"
	echo "[#] BASIC done as part of FULL."

    BASIC

    FULL_DIR="$OUTPUT_DIR/FULL_SCAN"
    mkdir -p "$FULL_DIR"

    if [ -d "$OUTPUT_DIR/BASIC_SCAN" ]; then
        echo "[*] Moving BASIC SCAN RESULTS into FULL SCAN DIRECTORY..."
        mv "$OUTPUT_DIR/BASIC_SCAN" "$FULL_DIR/"
    fi
    BASIC_DIR="$FULL_DIR/BASIC_SCAN"


    echo "[*] Targeted vulners NSE on discovered open ports (from BASIC)..."

    TCP_PORTS=$(awk 'toupper($1)=="TCP"{print $3}' "$BASIC_DIR/open_services.txt" | sort -nu | paste -sd, -)
    UDP_PORTS=$(awk 'toupper($1)=="UDP"{print $3}' "$BASIC_DIR/open_services.txt" | sort -nu | paste -sd, -)

    VULN_SCAN_TCP="$FULL_DIR/nse_scan_tcp.txt"
    VULN_SCAN_UDP="$FULL_DIR/nse_scan_udp.txt"
    : > "$VULN_SCAN_TCP"; : > "$VULN_SCAN_UDP"

    if [ -n "$TCP_PORTS" ]; then
        echo "[#] NSE TCP ports: $TCP_PORTS"
        nmap -sV -Pn -n -p "$TCP_PORTS" --script vulners "$TARGET" -oN "$VULN_SCAN_TCP" >/dev/null 2>&1
    else
        echo "[i] No open TCP for NSE."
    fi
    if [ -n "$UDP_PORTS" ]; then
        echo "[#] NSE UDP ports: $UDP_PORTS"
        nmap -sU -sV -Pn -n -p "$UDP_PORTS" --script vulners "$TARGET" -oN "$VULN_SCAN_UDP" >/dev/null 2>&1
    else
        echo "[i] No open UDP for NSE."
    fi
echo "NSE Vulns scans saved in $VULN_SCAN_TCP $VULN_SCAN_UDP"    

OPEN_SERVICES_FILE="$BASIC_DIR/open_services.txt"
SEARCHSPLOIT_RESULTS="$FULL_DIR/searchsploit_results"

# ipver = "IP|VERSION__WITH__SPACES" - by 	GPT
ipver="$(awk 'NF>=5 && $5!="-"{ver=$5; for(i=6;i<=NF;i++) ver=ver" "$i; gsub(/ /,"__",ver); print $2 "|" ver}' "$OPEN_SERVICES_FILE")"

for v in $ipver; do
  ip="$(echo "$v" | awk -F'|' '{print $1}')"
  version_enc="$(echo "$v" | awk -F'|' '{print $2}')"
  version="$(echo "$version_enc" | sed 's/__/ /g')"  

  echo "searchsploit -w --disable-colour \"$version\"   # $ip" >> "$SEARCHSPLOIT_RESULTS"
  searchsploit -w --disable-colour "$version" >> "$SEARCHSPLOIT_RESULTS"
  echo "-----" >> "$SEARCHSPLOIT_RESULTS"
done

echo "==== searchsploit finished and exported to $SEARCHSPLOIT_RESULTS"
}
#4. Log Results
#4.1 During each stage, display the stage in the terminal.
#4.2 At the end, show the user the found information.
#4.3 Allow the user to search inside the results.
#4.4 Allow to save all results into a Zip file.

SEARCH_RESULTS_LOOP() {
    while true; do
        read -p "Search inside results for a keyword? (yes/no): " search_choice
        if [[ "$search_choice" == "yes" ]]; then
            read -p "Enter keyword: " keyword
            echo -e "\nSearch results for '$keyword':"
            grep -R -n -i "$keyword" "$OUTPUT_DIR" || echo "[i] No matches."
            echo
        elif [[ "$search_choice" == "no" ]]; then
            break
        else
            echo "Invalid choice. Enter yes/no."
        fi
    done
}

SAVE_ZIP() {
    read -p "Archive results into ZIP? (yes/no): " save_choice
    if [[ "$save_choice" == "yes" ]]; then
        ZIP_NAME="${OUTPUT_DIR}.zip"
        # Archive quietly; suppress zip output
        zip -r "$ZIP_NAME" "$OUTPUT_DIR" >/dev/null 2>&1 && echo "[+] Saved to $ZIP_NAME" || echo "[-] ZIP failed."
    else
        echo "[i] Not archived."
    fi
}

###1.3 Allow the user to choose 'Basic' or 'Full'.
MENU() {
    read -p "Please choose the scanning level [B/F]. B=BASIC, F=FULL: " LEVEL
    case $LEVEL in
        B|b) BASIC ;;
        F|f) FULL ;;
        *)   MENU ;;
    esac
}

####Checking if required tools are installed
install_required_tools() {             
    local TOOLS=( "nmap" "masscan" "hydra" "exploitdb" "zip" "wget" "medusa" )
    echo "[+] Installing tools (existing won't be reinstalled)"
    # Update package lists quietly
    sudo apt-get update -y >/dev/null 2>&1

    for package_name in "${TOOLS[@]}"; do
        dpkg -s "$package_name" >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "[*] Installing $package_name..."
            # Install the package quietly
            sudo apt-get install -y "$package_name" >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "[#] $package_name installed."
            else
                echo "[-] Failed to install $package_name."
            fi
        else
            echo "[#] $package_name already installed."
        fi
    done

###Checking if NSE scripts is avaiable
    if [ ! -f "/usr/share/nmap/scripts/telnet-brute.nse" ]; then
        echo "[*] Installing Nmap telnet-brute NSE script..."
        sudo wget -q "https://svn.nmap.org/nmap/scripts/telnet-brute.nse" -O "/usr/share/nmap/scripts/telnet-brute.nse"
        sudo nmap --script-updatedb >/dev/null 2>&1
        if [ -f "/usr/share/nmap/scripts/telnet-brute.nse" ]; then
            echo "[#] telnet-brute.nse installed."
        else
            echo "[-] Failed to install telnet-brute.nse."
        fi
    fi
    if [ ! -f "/usr/share/nmap/scripts/vulners.nse" ]; then
        echo "[*] Installing Nmap vulners NSE script..."
        sudo wget -q "https://svn.nmap.org/nmap/scripts/vulners.nse" -O "/usr/share/nmap/scripts/vulners.nse"
        sudo nmap --script-updatedb >/dev/null 2>&1
        if [ -f "/usr/share/nmap/scripts/vulners.nse" ]; then
            echo "[#] vulners.nse installed."
        else
            echo "[-] Failed to install vulners.nse."
        fi
    fi
    
#Creating users and passwords list
echo -e "admin\n1234\n12345\n123456\npassword\nroot\ntoor\nuser\ntest\nguest\nftp\ntomcat\nmsfadmin" > "$SCRIPT_DIR/passwords.txt"
echo "Defaults user list downloaded and saved in $SCRIPT_DIR/passwords.txt"
echo -e "admin\nroot\nuser\ntest\nguest\nftp\ntomcat\nmsfadmin\nanonymous\nadministrator" > "$SCRIPT_DIR/users.txt"
echo "Defaults user list downloaded and saved in $SCRIPT_DIR/users.txt"
echo -e "admin:admin\nadmin:1234\nadmin:12345\nadmin:123456\nadmin:password\nroot:root\nroot:toor\nroot:1234\nroot:123456\nuser:user\ntest:test\nguest:guest\nftp:ftp\ntomcat:tomcat\nmsfadmin:msfadmin\nmsfadmin:1234\nmsfadmin:12345\nmsfadmin:123456\nmsfadmin:password\nadministrator:password\nadministrator:123456\nadministrator:12345\nadministrator:1234\nanonymous:" > "$SCRIPT_DIR/weak_passwords.lst"
echo "Defaults passwords + user list downloaded and saved in $SCRIPT_DIR/weak_passwords.lst"

}

START() {
## 1. Getting the User Input, 1.1 Get from the user a network to scan., 1.2 Get from the user a name for the output directory. + Validate inputs are correct
    while true; do
        echo "Target IP or CIDR (e.g. 192.168.1.5 or 192.168.1.0/24):"
        read NET
        if echo "$NET" | grep -q "/"; then
            IP=$(echo "$NET" | cut -d/ -f1)
            PREFIX=$(echo "$NET" | cut -d/ -f2)
        else
            IP="$NET"; PREFIX=""
        fi
        DOTS=$(echo "$IP" | grep -o "\." | wc -l)
        if [ "$DOTS" -ne 3 ]; then echo "[!] Bad IP format."; continue; fi
        oct1=$(echo "$IP" | cut -d. -f1)
        oct2=$(echo "$IP" | cut -d. -f2)
        oct3=$(echo "$IP" | cut -d. -f3)
        oct4=$(echo "$IP" | cut -d. -f4)
        VALID_IP=true
        for oc in "$oct1" "$oct2" "$oct3" "$oct4"; do
            if ! echo "$oc" | grep -q '^[0-9]\+$'; then VALID_IP=false; fi
            if [ "$oc" -lt 0 ] || [ "$oc" -gt 255 ]; then VALID_IP=false; fi
        done
        if [ "$oct1" -eq 0 ]; then
            VALID_IP=false
        fi

        [ "$VALID_IP" != true ] && { echo "[!] Bad IP."; continue; }

        if [ -n "$PREFIX" ]; then
            echo "$PREFIX" | grep -q '^[0-9]\+$' || { echo "[!] Bad CIDR."; continue; }
            if [ "$PREFIX" -lt 0 ] || [ "$PREFIX" -gt 32 ]; then echo "[!] CIDR 0–32."; continue; fi
        fi
        echo "[✓] Valid target: $NET"
        break
    done

    echo "Output directory name:"
    read dir_name
    [ -z "$dir_name" ] && { dir_name="SCAN_RESULTS"; echo "[i] Using SCAN_RESULTS"; }
    while [ -d "$dir_name" ]; do
        echo "[!] Directory exists. Choose another:"
        read dir_name
        [ -z "$dir_name" ] && dir_name="SCAN_RESULTS"
    done
    mkdir "$dir_name"
    echo "[+] Created: $dir_name"

    TARGET="$NET"
    OUTPUT_DIR="$dir_name"

    install_required_tools
    MENU
    SEARCH_RESULTS_LOOP
    SAVE_ZIP

    echo "[+] Logs at: $OUTPUT_DIR"
    echo "[*] Files:"
    find "$OUTPUT_DIR" -type f
    echo "[✓] Done."
    exit 0
}

START

