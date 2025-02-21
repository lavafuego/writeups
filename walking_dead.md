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



