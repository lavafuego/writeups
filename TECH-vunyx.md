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

