## DESCARGA Y MONTAJE DE MÁQUINA VICTIMA

Nos dirigimos a la página:

![Nmap Scan](images/PingCTF/1.png)

```bash
https://dockerlabs.es/
```

y alli a al enlace de la máquina vulnerable llamada `PingCTF` del autor: `borazuwarah`:

```bash
https://mega.nz/file/jVdVyYYK#Cl7k02bD1IHF6_j1tljf497k4l7uPq2QxzJQvs1tqoY
```

![Nmap Scan](images/PingCTF/2.png)


movemos la descarga a la carpeta de trabajo con:

```bash
mv /ruta_a_mi_carpeta_de_trabajo
```
descargamos con un unzip el contenido comprimido con zip:

```bash
unzip PingCTF.zip
```

y ejecutamos este comando para subir la máquina vulnerable

```bash
sudo bash auto_deploy.sh ping_ctf.tar
```


![Nmap Scan](images/PingCTF/3.png)
