## MONTAMOS MÁQUINA VULNERABLE

1-Vamos a la página `https://dockerlabs.es/` y buscamos la máquina ´Profetas´ nivel medio y su autor `mikisbd`

2- descargamos el zip

3-descomprimimos el zip con:

```bash
 unzip profetas.zip
```

4- montamos la máquina vulnerable en docker con los archivos descomprimidos en el zip:

```bash
sudo bash auto_deploy.sh profetas.tar
```

5- una vez montada nos dice que la IP del la máquina vulnerable es `172.17.0.2`

![Imagen](images/Profetas/1.png)
