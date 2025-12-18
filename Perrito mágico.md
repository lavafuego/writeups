

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

