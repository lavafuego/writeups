*Autor:JuanR*
Levantamos el docker:
```bash
sudo bash auto_deploy.sh patriaquerida.tar 
```
y nos levanta la maquina víctima con la IP:172.17.0.2

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
