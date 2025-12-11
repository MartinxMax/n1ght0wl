#!/bin/bash
# $ ./ms17-010_scanner.sh --ips <A|B|C>/<Time>.nps
IPS_FILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ips)
            IPS_FILE="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -z "$IPS_FILE" ]]; then
    echo "Usage: $0 --ips <file>"
    exit 1
fi

echo "[*] Starting automated scan (Per subnet → Host discovery → MS17-010 detection)..."
echo

while read -r SUBNET; do
    [[ -z "$SUBNET" ]] && continue

    echo "=============================================="
    echo "[*] Current subnet: $SUBNET"
    echo "=============================================="

 
    echo "[*] Discovering live hosts..."
    ALIVE_IPS=$(nmap -sn "$SUBNET" -oG - | awk '/Up$/{print $2}')

    if [[ -z "$ALIVE_IPS" ]]; then
        echo "[-] No live hosts"
        continue
    fi

    for ip in $ALIVE_IPS; do
        echo " [+] Live: $ip"
    done

    echo
    echo "[*] Running MS17-010 detection on $SUBNET..."

    TMP=$(mktemp)

 
    nmap -Pn -p445 --script smb-vuln-ms17-010 $ALIVE_IPS -oN "$TMP" > /dev/null 2>&1

    echo
    echo "[*][$SUBNET] Hosts vulnerable to MS17-010:"

 
    VULN_IPS=$(
        awk '
            /Nmap scan report/{ip=$5}
            /VULNERABLE/{print ip}
        ' "$TMP" | sort -u
    )

    if [[ -z "$VULN_IPS" ]]; then
        echo "  [-] No vulnerable hosts"    
    else
        for vip in $VULN_IPS; do
            echo "  [+] $vip"
        done
    fi

    echo
    rm -f "$TMP"

done < "$IPS_FILE"
