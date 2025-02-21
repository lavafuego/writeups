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




