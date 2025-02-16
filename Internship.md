Después de desplegar la máquina nos dice que su IP es 172.17.0.2, comprobamos trazabilidad
```bash
ping -c 1 172.17.0.2
```
```
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.035 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.035/0.035/0.035/0.000 ms
```
1 paquete transmitido, 1 recibido, cero perdidos, está todo correcto

## FASE DE ENUMERACIÓN

Vamos a enumerar los puertos abiertos, ver que servicios corren por ellos y su versión por si hay alguna vulnerabilidad:
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 35:ff:c4:8b:c4:e1:46:12:43:b9:03:a9:cf:ec:f3:0a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMLcU0NdLlcMjGTvMebPUhkYyTefstC3io0s5l3Mx8OHiNGXN2kbbXgN2v5q/leJOxatqm0YaNUXO0fFc8nHCok=
|   256 23:ac:95:1e:be:33:9e:ed:14:f0:45:f6:27:51:ca:ba (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOKYORvyjT35RDCNPL0y+KJc/uIqXKC8OskWAJEmmqS
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: GateKeeper HR | Tu Portal de Recursos Humanos
```

Puerto 22 con ssh en versión no vulnerable y sin credenciales. Vamos a centrarnos en el 80.
lanzamos un whatweb para ver si reporta algo interesante:
```bash
whatweb http://172.17.0.2
```
```
http://172.17.0.2 [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], PasswordField[password], Script, Title[GateKeeper HR | Tu Portal de Recursos Humanos], UncommonHeaders[x-virtual-host]
```

veo esto: UncommonHeaders[x-virtual-host] , lo cual me hace pensar en virtualhostin, abro la página y miro el código fuente y veo esto:

```
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GateKeeper HR | Tu Portal de Recursos Humanos</title>
    <link rel="dns-prefetch" href="//gatekeeperhr.com" />
```
así pués lo añado en el /etc/hosts, además no me deja abrir nada de la página.
 ```bash
sudo nano /etc/hosts
```
```
172.17.0.2      gatekeeperhr.com
```
antes de abrir el dominio compruebo si hay más subdominios:
```bash
 wfuzz -c --hc=404 --hh=3861 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.gatekeeperhr.com" http://gatekeeperhr.com/
```
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://gatekeeperhr.com/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                     
=====================================================================

000000001:   200        108 L    235 W      3971 Ch     "www"
```
hay uno más que añado al /etc/hosts qyedando así la cosa:
```
172.17.0.2      gatekeeperhr.com www.gatekeeperhr.com
```

hago fuzzing y encuentro esta rutas:
```
200      GET      241l      406w     3387c http://gatekeeperhr.com/css/styles.css
200      GET        1l       89w    14999c http://gatekeeperhr.com/js/script.js
200      GET      108l      235w     3971c http://gatekeeperhr.com/
200      GET      108l      235w     3971c http://gatekeeperhr.com/index.html
200      GET       92l      188w     3140c http://gatekeeperhr.com/contact.html
200      GET       90l      231w     3339c http://gatekeeperhr.com/about.html
301      GET        9l       28w      319c http://gatekeeperhr.com/spam => http://gatekeeperhr.com/spam/
301      GET        9l       28w      322c http://gatekeeperhr.com/default => http://gatekeeperhr.com/default/
301      GET        9l       28w      318c http://gatekeeperhr.com/css => http://gatekeeperhr.com/css/
301      GET        9l       28w      323c http://gatekeeperhr.com/includes => http://gatekeeperhr.com/includes/
301      GET        9l       28w      317c http://gatekeeperhr.com/js => http://gatekeeperhr.com/js/
301      GET        9l       28w      318c http://gatekeeperhr.com/lab => http://gatekeeperhr.com/lab/
200      GET        0l        0w        0c http://gatekeeperhr.com/includes/db.php
200      GET      241l      406w     3387c http://gatekeeperhr.com/default/styles.css
200      GET      107l      220w     3861c http://gatekeeperhr.com/default/index.html
200      GET       14l       32w      308c http://gatekeeperhr.com/spam/index.html
405      GET        1l        4w       61c http://gatekeeperhr.com/lab/login.php
200      GET        1l       14w      867c http://gatekeeperhr.com/lab/employees.php
```

abro  http://gatekeeperhr.com/lab/employees.php y me encuentro esto:
```
{"status":"success","employees":[{"id":"1","name":"Ana Garcia","department":"Ventas","startDate":"2023-05-15"},{"id":"2","name":"Carlos Rodriguez","department":"IT","startDate":"2023-06-01"},{"id":"3","name":"Maria Lopez","department":"Recursos Humanos","startDate":"2023-06-10"},{"id":"4","name":"Juan Martinez","department":"Marketing","startDate":"2023-06-15"},{"id":"5","name":"Laura Sanchez","department":"Finanzas","startDate":"2023-07-01"},{"id":"6","name":"Pedro Ramirez","department":"Pasantia IT","startDate":"2023-07-05"},{"id":"7","name":"Sofia Torres","department":"Ventas","startDate":"2023-07-10"},{"id":"8","name":"Diego Herrera","department":"IT","startDate":"2023-07-15"},{"id":"9","name":"Valentina Gomez","department":"Pasantia IT","startDate":"2023-07-20"},{"id":"10","name":"Alejandro Vargas","department":"Marketing","startDate":"2023-07-25"}]}
```

así pues me creo un diccionario de nombres:
```
anagarcia
carlosrodriguez
marialopez
juanmartinez
laurasanchez
pedroramirez
sofiatorres
diegoherrera
valentinagomez
alejandrovargas
ana
carlos
maria
juan
laura
pedro
sofia
diego
valentina
alejandro
garcia
rodriguez
lopez
martinez
sanchez
ramirez
torres
herrera
gomez
vargas
```

luego voy a esta ruta: http://gatekeeperhr.com/spam/index.html y en su código fuente veo esto:
```
<!-- Yn pbagenfrñn qr hab qr ybf cnfnagrf rf 'checy3' -->
```

