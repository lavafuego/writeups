## DESLIEGUE DEL DOCKER
1- En nuestra máquina de atacante descargamos el archivo zip (walking_dead.zip) de esta página:
```bash
https://mega.nz/file/KYF0CAia#VZDiYoAnlpQ1n61yLqOkFfCApsLeqOgPL9Hyoi8tzgM
```

2- Descomprimimos el contenido
```bash
unzip walking_dead.zip
```
3- Por limpieza eliminamos el zip (opcional)
```bash
rm walking_dead.zip
```

4- Desplegamos el docker
```bash
sudo bash auto_deploy.sh walking_dead.tar
```
  *Explicación:*
    
    -sudo: ejecutamos los comandos con privilegios se superusuario (root)
    -bash auto_deploy.sh: ejecutamos el script auto_deploy.sh con el interprete de comandos bash
    -walking_dead.tar: un archivo comprimido en tar que se pasa como argumento al script auto_deploy.sh necesario para que se ejecute correctamente

5- Una vez desplegada nos indica que su IP es--> 172.17.0.2


## FASE DE RECONOCIMIENTO

Lanzamos un scaneo de puertos para ver cuales tiene abiertos, que servicios corren por ellos y su versión por si presentan alguna vulnerabilidad

```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
  *Explicación:*
   
    -sudo: ejecutamos los comandos con privilegios se superusuario (root), el tipo de scan sS solo puede realizarlo root
    -nmap: herramienta para realizar el scan de puertos
    -sS: Realiza un escaneo SYN (también conocido como "half-open" o "stealth scan"). Envía paquetes SYN a los puertos y, según la respuesta (SYN/ACK o RST), determina si el puerto está abierto o cerrado sin completar el handshake TCP
    -sCV: opcion que junta -sC y -sV, sC para detectar configuraciones y servicios y sV para detectar las versiones
    -Pn: nos saltamos el descubrimientos de host e indicamos que este está activo
    - --min-rate 5000:Configura una tasa mínima de envío de 5000 paquetes por segundo, lo que acelera el escaneo
    - -p-: indica todos los puertos (desde el 1 hasta el 65535).
    - vvv: verbosidad o reporte inmediato en tasa alta
    - --open: muestra solo los puertos abiertos en la consola
    - 172.17.0.2: IP a la que lanzamos el escaneo de puertos
    -oN: guardamos los resultados en formato nmap en el archivo con el nombre que vaya seguido de la opcion
    -PuertosYservicios: salida del scan nombrado así y en formato nmpa por el comando anterior
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0d:09:9d:0f:dc:43:54:cd:39:a9:e2:d6:81:74:40:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8d0fsEXMyaaTUTpqil+QprMddl5db/38VYTaZvPf9i7/Ws8Sj2pbyiiHoho8hBhjSsFVfxOJNX2hk4jpKXq0uPUN43zu7GQfuGNMF/YfCbvINXJhtWzjb8avarscC/fohusNGrzNsqb86q8tYxzzdsauIrE1pjDl/duqp/hTMG3TFJJFOvwq3Bj7bReWwglO4nyQZuH6mE7Wt+yW2O0KnoxHzgShxOJ7bkFG8TMdzEMX8VVj8wuGJ3Y53+KQzPdxec8cn4S8Ks2IrJUISMMGxZyjIPPNagjL9T79m1kbttCUQaaeFGJPEU6WG+RBbe+ckMs04b0ZkhaKFaK6mBeLffztZwV1XBTs5s2QKG9jAYRLc7pyBrZLYOsPMrdsyU7DFlu2A2Lat+NO7tysOHHUEehFngYAcw9eZ6+bY4vbJ2n8N6JmpQbuIs9MNEf+hT9mb0NWXJeagXxjm4z4AdnLTzEyNUf8S2Rni3NrSdeEP/BnYnLNof6NP0YZwdpscf2s=
|   256 09:d0:f6:52:00:3f:21:51:19:b1:c6:7a:f4:ff:21:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH/N+/wQW5dfRppBa2kxFVVQnFEF/eI+3WI6rt4HqcIFku8RAqMewPqIIRqeEVg76oI0Z8VYWJAHrjURU5wtAOs=
|   256 19:e0:b3:72:bd:e9:1e:8d:4c:c4:fd:1f:da:3f:a5:cf (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOdAdIFZiY24Teo7S5rSd5GcC7nCagj60uCMS6ug47ck
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: The Walking Dead - CTF
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
```

Tenemos dos puertos abiertos, el 22 por el cual corre SSH en su versión 8.2 no vulnerable y el puerto 80 http,
como  no tenemos usuario ni password para el servicio ssh o alguno de ellos para lanzar un ataque por fuerza bruta nos centraremos
en el servicio http, vamos a lanzar un wharweb para ver si nos reporta algo:
```bash
whatweb http://172.17.0.2
```
```
http://172.17.0.2 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[172.17.0.2], Title[The Walking Dead - CTF]
```
A parte de que corre un apache poco más podemos sacar, abrimos en el navegador la página.
Uso como navegador firefox, con ctrl+u miro el código fuente y no veo nada

Decido hacer fuzzing para ver si encuentro alguna ruta activa
```bash
gobuster dir -u "http://172.17.0.2/" -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,html,php
```
*Explicación:*
- **gobuster**: Es una herramienta que realiza fuerza bruta para descubrir directorios y archivos ocultos en servidores web.
- **dir**: Especifica el modo de operación, en este caso, el escaneo de directorios.
- **-u "http://172.17.0.2/"**: Define la URL objetivo a la que se le realizará el escaneo.
- **-w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt**: Indica la ruta del archivo de wordlist, que contiene una lista de posibles nombres de directorios y archivos que se intentarán descubrir.
- **-x txt,html,php**: Especifica las extensiones que se le añadirán a cada término de la wordlist para buscar archivos con esos formatos (por ejemplo, index.txt, index.html, index.php).

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 1380]
/backup.txt           (Status: 200) [Size: 53]
/hidden               (Status: 301) [Size: 309] [--> http://172.17.0.2/hidden/]
/.html                (Status: 403) [Size: 275]
/.php                 (Status: 403) [Size: 275]
/server-status        (Status: 403) [Size: 275]
Progress: 882184 / 882188 (100.00%)
===============================================================
Finished
===============================================================
```

Veo un archibo backup.txt y una ruta /hidden, primero voy a ver el archivo.
Abro la ruta:
```bash
http://172.17.0.2/backup.txt
```
en el buscador y puedo leero:
```
Error 403: Forbidden. Directory listing is disabled.
```
Nos vamos a centrar en el directorio hidden, primeramente lanzo un scaneo normal con gobuster y no encuentro nada,
pero intuyendo que no hay otra cosa que rascar, lanzo un scan con otra herramienta
```bash
 feroxbuster -u "http://172.17.0.2" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php,html,txt,js,old,bak
```
y esta vez veo una ruta nueva:
```
200      GET        0l        0w        0c http://172.17.0.2/hidden/.shell.php
```

recordando el backup.txt que nos decía que no se pueden listar directorios, intento fuerzabruta al php pero con un comando por ejemplo "id"

```bash
 wfuzz -c --hc=404 --hh=0 -w /opt/SecLists/Discovery/Web-Content/big.txt  "http://172.17.0.2/hidden/.shell.php?FUZZ=id"
```
*Explicación:*
 - **wfuzz**: Herramienta para realizar fuzzing en aplicaciones web, permitiendo probar múltiples entradas en parámetros de URLs.
- **-c**: Muestra la salida en color, lo que facilita la identificación de resultados relevantes.
- **--hc=404**: Excluye las respuestas que retornen el código HTTP 404 (Not Found), para filtrar resultados no deseados.
- **--hh=0**: Oculta las respuestas cuyo tamaño (header) sea 0, eliminando resultados vacíos.
- **-w /opt/SecLists/Discovery/Web-Content/big.txt**: Especifica la wordlist que se utilizará, en este caso, el archivo 'big.txt' ubicado en la ruta dada.
- **"http://172.17.0.2/hidden/.shell.php?FUZZ=id"**: Es la URL objetivo donde se reemplazará la palabra clave `FUZZ` por cada entrada de la wordlist, permitiendo identificar posibles recursos o comportamientos en el parámetro `id`.

```
000004749:   200        1 L      3 W        54 Ch       "cmd"
```
ya podemos ejecutar desde la url comnandos


## FASE INTRUSIÓN







