## DESPLEGAMOS LA MÁQUINA VULNERABLE

Descargamos la máquina vulnerable y descomprimimos con `unzip internal.zip` eso nos descomprime dos archivos para montar un docker con la máquina

usamos el comando `sudo bash auto_deploy.sh internal.tar`

![Imagen](images/internal/1.png)

## FASE ESCANEO E INTRUSIÓN

Realizamos un scaneo de puertos, para ver cuales tiene abiertos, que servicios corre por ellos y si son vulnerables:
```bash
sudo nmap -sS -sCV --open -p- --min-rate 5000 172.17.0.2 -vvv -oN nmap
```

![Imagen](images/internal/2.png)


![Imagen](images/internal/3.png)



Vemos dos puertos abiertos
-22 con SSh versión no vulnerable
-80 http

Dado que no tenemos user ni password para conectarnos por SSH nos vamos a centrar en el puerto 80, antes de ir a la página web
vamos a lanzar un whatweb para ver que reporta:

```bash
whatweb http://172.17.0.2 | tee whatweb
```


![Imagen](images/internal/4.png)


Vemos un virtual hosting ` http://internal.dl/` vamos a añadir el dominio, abrimos con nano el `/etc/hosts` y lo añadimos

```bash
sudo nano /etc/hosts
```
![Imagen](images/internal/5.png)

Una vez realizado, antes de entrar en la web vamos a buscar subdominios:

```bash
 gobuster vhost -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt  -u 'http://internal.dl' --append-domain --exclude-status 303
```

![Imagen](images/internal/6.png)


Descubrimos un subdominio que añadimos al `/etc/hosts` quedando así:


![Imagen](images/internal/7.png)


Vamos a visitar el subdominio y ver que pasa.


![Imagen](images/internal/8.png)


Vemos un `directory inspector` que nos hace una especie de ls -la de rutas, vamos a hacer una captura con burpsuite para ver como se comporta:









