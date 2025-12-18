

## DESCARGA Y MONTAJE DE LA MÁQUNA

1-Nos vamos a la página ´https://dockerlabs.es/´ y buscamos la máquina vulnerable ´Perrito Mágico´

2-La descargamos en nuestra máquina kali 

3- descomprimimos con:

```bash
unzip perrito_magico.zip
```

4- usamos este comando para levantar el docker:

```bash
sudo bash auto_deploy.sh perrito_magico.tar
```

![Nmap Scan](images/perrito/1.png)



## FASE DE ENUMERACIÓN

Realizamos un scaneo de puertos para ver cuales tiene abiertos, que servicios corren por ellos y que versión por si presentan alguna vulnerabilidad:

```bash
sudo nmap -sS -sCV --open -p- --min-rate 5000 172.17.0.2 -vvv -oN nmap
```

![Nmap Scan](images/perrito/2.png)


![Nmap Scan](images/perrito/3.png)


Vemos que tiene el puerto 22 por el cual corre una version SSH no vulnerable y el puerto 5000 con HTTP, vamos a centrarnos en el HTTP


Lanzamos un curl para ver las cabeceras y un whatweb para ver si reporta algo interesante:

```bash
curl -I 172.17.0.2:5000
```
```bash
whatweb http://172.17.0.2:5000 | tee whatweb
```


![Nmap Scan](images/perrito/4.png)

Vemos una cookie, una redirección... vamos a abrir el navegador:



![Nmap Scan](images/perrito/5.png)


Reviso por encima el código fuente veo alguna cosa pero me centro en buscar rutas:

```bash
 gobuster dir -u "http://172.17.0.2:5000/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php, ,html
```

![Nmap Scan](images/perrito/6.png)


veo una ruta interesante `http://172.17.0.2:5000/api/]`

la abro en el navegador:


![Nmap Scan](images/perrito/7.png)


Por lo visto aquí tenemos la forma de cambiar la foto de la máquina


![Nmap Scan](images/perrito/8.png)

Ya que tenemos la ruta, la visitamos en la web y:


![Nmap Scan](images/perrito/9.png)


error...si miramos la descripcion de como funciona esto en ´http://172.17.0.2:5000/api/´, concretamente desplegando el panel vemos que es obligatorio enviar tres campos:

```
machine_id 
origen 
logo 
```
![Nmap Scan](images/perrito/8.png)

vamos a trastear un poco más por si vemos algo que nos ayude:

![Nmap Scan](images/perrito/10.png)


![Nmap Scan](images/perrito/11.png)


podemos ver que la id de la máquina es un intiger, que el origen puede ser  `docker` o `bunker` y el logo una imagen que subamos, repaso un poco curl antes de ponerme al lio y mi primer intento:






