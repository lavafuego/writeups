**Autor**: Hack_Viper

## Paso 1: Levantamos el Docker
Para comenzar, ejecutamos el script de despliegue del contenedor con el siguiente comando:

```bash
sudo bash auto_deploy.sh extraviado.tar
```
Dirección IP de la Máquina: 172.17.0.2

A continuación, realizamos un escaneo de puertos y servicios y lo exportamos en formato Nmap a un archivo llamado PuertosYservicios:
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 cc:d2:9b:60:14:16:27:b3:b9:f8:79:10:df:a1:f3:24 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBP+OTZeMj+iOYGoGNHCDrHUIQkt2SFwk2xRrNbDmWaMzKU2VijE4vADaT1p2MEwe5CYAks/5ZWAc53IbmeEKD4k=
|   256 37:a2:b2:b2:26:f2:07:d1:83:7a:ff:98:8d:91:77:37 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJrTvCLEYLPYegFzNm0ZZPbG02YvabBcv7CH6nhpbBKH
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
```
**Explicación**: 

-El puerto 22 está abierto para SSH, con la versión de OpenSSH 9.6p1.

-El puerto 80 está abierto para HTTP, con Apache 2.4.58 en Ubuntu.

No teniendo credenciales y siendo una version no vulnerable de SSH nos vamos a centrar en el puerto 80, pero antes de entrar
de lleno en la pagina web vamos a lanzar un pequeño escaneo guardando su salida

```bash
whatweb 172.17.0.2 -v | tee whatweb
```

nos da este resultado :

```
WhatWeb report for http://172.17.0.2
Status    : 200 OK
Title     : Apache2 Ubuntu Default Page: It works
IP        : 172.17.0.2
Country   : RESERVED, ZZ

Summary   : Apache[2.4.58], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.58 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : Apache/2.4.58 (Ubuntu) (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Wed, 15 Jan 2025 12:26:29 GMT
        Server: Apache/2.4.58 (Ubuntu)
        Last-Modified: Sat, 11 Jan 2025 21:43:14 GMT
        ETag: "2a5c-62b75192fe080-gzip"
        Accept-Ranges: bytes
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 3157
        Connection: close
        Content-Type: text/html
```

No apreciamos nada, así que visitamos la web

```
WhatWeb report for http://172.17.0.2
Status    : 200 OK
Title     : Apache2 Ubuntu Default Page: It works
IP        : 172.17.0.2
Country   : RESERVED, ZZ

Summary   : Apache[2.4.58], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.58 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : Apache/2.4.58 (Ubuntu) (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Wed, 15 Jan 2025 12:26:29 GMT
        Server: Apache/2.4.58 (Ubuntu)
        Last-Modified: Sat, 11 Jan 2025 21:43:14 GMT
        ETag: "2a5c-62b75192fe080-gzip"
        Accept-Ranges: bytes
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 3157
        Connection: close
        Content-Type: text/html
```


vemos que la pagina es la que trae por defecto ubuntu, pero miramos el código fuente, el la parte final vemos esto:
```
#.........................................................................................................ZGFuaWVsYQ== : Zm9jYXJvamE=
```
parece base 64 y procedemos a decodificarla:
```bash
echo "ZGFuaWVsYQ=="  | base64 -d; echo
```
nos da como salida daniela y procedemos con la otra parte:
```bash
echo "Zm9jYXJvamE="  | base64 -d; echo
```
nos da como salida: focaroja

tenemos un user y un pass daniela:focaroja

probamos con ssh y las credenciales:
```bash
ssh daniela@172.17.0.2
```
introducimos el pass cuando nos lo pide y estamos dentro

Aquí por defecto lo primero que miro es la variable de entorno con
```bash
printenv
```
no hay nada relevante
miro los uduarios:
```bash
cat /etc/passwd | grep sh$
````
*explicacion:* hacemosun cat al archivo passwd y lo grepeamos para que solo nos liste lo que termine en sh 
dándonos esta salida:

```
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
diego:x:1001:1001:diego,,,:/home/diego:/bin/bash
daniela:x:1002:1002:daniela,,,:/home/daniela:/bin/bash
```
dos usuarios potenciales más el root.
vamos a mirar y listar lo que hay en el home del usuario daniela incluidos archivos ocultos:
```bash
ls -la
```

```
drwxr-x--- 1 daniela daniela 4096 Jan 15 06:26 .
drwxr-xr-x 1 root    root    4096 Jan  9 19:57 ..
-rw-r--r-- 1 daniela daniela  220 Jan  9 19:57 .bash_logout
-rw-r--r-- 1 daniela daniela 3771 Jan  9 19:57 .bashrc
drwx------ 2 daniela daniela 4096 Jan 15 06:26 .cache
drwxrwxr-x 3 daniela daniela 4096 Jan  9 20:33 .local
-rw-r--r-- 1 daniela daniela  807 Jan  9 19:57 .profile
drwxrwxr-x 2 daniela daniela 4096 Jan  9 20:47 .secreto
drwxrwxr-x 2 daniela daniela 4096 Jan  9 20:35 Desktop
```
ese directorio con nombre "secreto" parece tener chicha, vemos lo que contiene.
Tiene un archivo de nombre passdiego, interesante, miramos que contiene:
```bash
cat passdiego
```
```
YmFsbGVuYW5lZ3Jh
```
un base 64, lo decodeamos:
```bash
echo "YmFsbGVuYW5lZ3Jh" | base64 -d; echo
```
y nos da la salida de 
```
ballenanegra
```
parece que tenemos el user diego y su pass ballenanegra
intentamos migrar de usuario:

```bash
su diego
```
e introducimos el pass cuando lo pide
ya somos Diego.
ahora nos vamos al home de diego con "cd"
y listamos los archgivos nuevamente con "la -la"
hay un arcvhivo llamado pass que si lo leememos:
```bash
cat pass
```
```
donde estara?
```

hay que buscar más, vemos una carpeta interesante:
```bash
cd .passroot/
```
```bash
ls -la
```
```bash
```
drwxrwxr-x 1 diego diego 4096 Jan 11 14:29 .
drwxr-x--- 1 diego diego 4096 Jan  9 21:11 ..
-rw-rw-r-- 1 diego diego   21 Jan 11 14:29 .pass
```
hacemos cat y nos da un base64 nuevamente

```bash
cat .pass
```
```
YWNhdGFtcG9jb2VzdGE=
```
decodeamos:
```bash
echo "YWNhdGFtcG9jb2VzdGE=" | base64 -d; echo
```
```
acatampocoesta
```
buen troleo jajajaja

a seguir buscando
volvemos al home y probamos con la carpeta .local, que contiene otra que se llama share y ojo¡¡¡
```
~/.local/share$ ls -la
total 16
drwx------ 1 diego diego 4096 Jan 11 15:33 .
-rw-r--r-- 1 root  root   319 Jan 11 15:33 .-
drwxrwxr-x 1 diego diego 4096 Jan  9 20:51 ..
drwx------ 2 diego diego 4096 Jan  9 20:51 nano
```
un punto seguido de un guión?:
```
s -la
total 16
drwx------ 1 diego diego 4096 Jan 11 15:33 .
-rw-r--r-- 1 root  root   319 Jan 11 15:33 .-
drwxrwxr-x 1 diego diego 4096 Jan  9 20:51 ..
drwx------ 2 diego diego 4096 Jan  9 20:51 nano
```

pues nada un cat y miremos que contiene:
```bash
cat ./.-
```
```
password de root

En un mundo de hielo, me muevo sin prisa,
con un pelaje que brilla, como la brisa.
No soy un rey, pero en cuentos soy fiel,
de un color inusual, como el cielo y el mar
tambien.
Soy amigo de los ni~nos, en historias de
ensue~no.
Quien soy, que en el frio encuentro mi due~no?

```

*adivina adivinanza*

aqui probé bastantes veces haste tener el root la clave es *osoazul*
```bash
su root
```
introducimos el pass: osoazul

```
diego@dockerlabs:~/.local/share$ su root
Password: 
root@dockerlabs:/home/diego/.local/share# whoami
root
```
