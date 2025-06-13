## Descarga y montaje de la máquina
desde https://dockerlabs.es/ buscamos la máquina vulnerable gallery, y bajamos el zip:
```bash
https://mega.nz/file/ONlzkaAC#xPFZFyFo_ZxcSN-DoOdI5yqp7UJb3ugxNnM23UzcRww
```
creamos una carpeta con su nombre:
```bash
mkdir Gallery
cd !$
```
  - mkdir crea la carpeta
  - cd !$ entra en el último argumento anterior que en este caso es "Gallery" es lo mismo que cd Galley

movemos el zip descargado a la carpeta:
```
mv /home/kali/Downloads/Gallery.zip .
```
  - mv mover o renombrar
  - ruta del archivo a mover
  - . punto directorio actual

descomprimimos
```bash
unzip Gallery.zip
```

eliminamos el zip para ser más limpios

```
rm Gallery.zip
```

montamos la máquina:

```bash
sudo bash auto_deploy.sh gallery.tar
```

monta la máquina en un docker y nos dice que su IP es:
```
Máquina desplegada, su dirección IP es --> 172.17.0.2
```

comprobamos trazabilidad:
```
ping -c 1 172.17.0.2                                                                                                                                                                                                   
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.065 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.065/0.065/0.065/0.000 ms

```
  - tenemos trazabilidad  "1 packets transmitted, 1 received, 0% packet loss, time 0ms"
  - con ttl=64 intuimos que es una máquina linux

## Fase de enumeración

usamos nmap para listar puertos abiertos, los servicios que hay corriendo por ellos y sus versiones:
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN puertosYservicios
```
  - sudo hay que ejecutarlo con privilegios el comando
  - nmap herramienta que vamos a utilizar
  - -sS escaneo tipo SYN escaneo más rápido porque no completa el handshake de tres pasos
  - -sCV escaneo de servicios y sus versiones es -sC -sV en un mismo comando
  - -Pn indicamos que no queremos que haga ping
  - --min-rate 5000 tasa minima de paquetes por segundo
  - -p- todo el rango de puertos, escanea los 65535
  - -vvv triple verbose para ver una salida detallada de lo que va encontrando
  - --open solo reporte puertos abiertos
  - -oN puertosYservicios exportamos los resultados en formato nmap al archivo puertosYservicios

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 19:95:1a:f2:f6:7a:a1:f1:ba:16:4b:58:a0:59:f2:02 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKhtMp0GLeYD8q+rHtaud0UjdMeeEVFzKSZoR8qk/rcwqBdb1LTRGhcbCnpJLD9FlVm6HYZO2BqU52epofJd6/o=
|   256 e7:e9:8f:b8:db:94:c2:68:11:4c:25:81:f1:ac:cd:ac (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCyYfXQ5yljb7YXITXrQFdCNEGjLRz56DnJb/C6gxIf
80/tcp open  http    syn-ack ttl 64 PHP cli server 5.5 or later (PHP 8.3.6)
|_http-title: Galer\xC3\xADa de Arte Digital
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
  - Puerto 22 ssh version 9.6 no vulnerable a listar usuarios
  - puerto 80 http

No teniendo usuarios para intentar fuerzabruta al servicio ssh nos centramos en el http

## enumeración de la página web

lanzamos un whatweb para ver que corre en la página:
```bash
whatweb 172.17.0.2 -v
```
no hay redirecciones y solo nos reporta interesante
```
 HTML5, PHP[8.3.6], X-Powered-By[PHP/8.3.6]
```
sin más, abrimos la página y miramos el código fuente con ctrl+u lo único que vemos es que el botón de login que nos lleva a /login.php

probamos inyeccion sql básica, en el username:
```
' or 1=1-- -
```
logramos inyectarla y nos logueamos llevándonos a :
```
http://172.17.0.2/dashboard.php
```

