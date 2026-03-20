


## DESCARGA Y MONTAJE DE LA MÁQUINA VULNERABLE

Vamos a la página `https://dockerlabs.es/` y allí buscamos la máquina `Flasky`. La descargamos en nuestro kali.
1-Hacemos `unzip flasky.zip` para descomprimir el contenido, esto nos crea dos archivos:
  `auto_deploy.s` y `flasky.tar`
2-Usamos los archivos descomprimidos para montar la máquina vulnerable en un docker:
  `sudo bash auto_deploy.sh flasky.tar`

  ![CTF(images/Flasky/1.png)
