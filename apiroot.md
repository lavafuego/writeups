Desplegamos en contenedor y nos indica que la máquina víctima tiene la IP-->172.17.0.2

Vamos a comprobar trazabilidad:
```bash
ping -c 1 172.17.0.2
```
```
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.085 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.085/0.085/0.085/0.000 ms
```
un paquete transmitido, uno recibido, cero perdidos.

## FASE DE ENUMERACIÓN

Escaneamos puertos abiertos, así como los servicios que corren por ellos y sus versiones por si son vulnerables
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 19:f1:08:79:13:c4:42:b8:6c:c8:a3:3e:f5:39:a3:59 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLJ6c9b2FZ+2/lQs+7H8j9Vkf83is1rphGqioHJ5Udw/zuClnjeZCCWS3dDNfsWKsmC4bDpP+fbL5p7z3Vpj5z0=
|   256 9b:93:02:4e:d2:08:f7:d7:eb:90:48:e4:48:17:1b:f5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILi2T2o/qZXjV7oo43koui/mZwrmfb2NgDELa++lV/sJ
5000/tcp open  http    syn-ack ttl 64 Werkzeug httpd 2.2.2 (Python 3.11.2)
|_http-title: \xC2\xBFQu\xC3\xA9 es una API?
|_http-server-header: Werkzeug/2.2.2 Python/3.11.2
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
```

-Puerto 22 SSH versión 9.2 no vulnerable, sin credenciales, lo descartamos

-Puerto 5000 http, nos vamos a centrar en él

Lanzamos un whatweb, por si nos reporta algo interesante

```bash
whatweb http://172.17.0.2:5000
```
```
http://172.17.0.2:5000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.11.2], IP[172.17.0.2], Python[3.11.2], Title[¿Qué es una API?], Werkzeug[2.2.2]
```

entro en la página y miro el código fuente sin ver nada interesante, leyendo la página supongo que hay un directorio "api" y hago fuzzing desde el mismo
```bash
wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  "http://172.17.0.2:5000/api/FUZZ"
```
```
000000188:   401        3 L      5 W        31 Ch       "users"   
```

me mueve al mismo, y es como que no estuviera autorizado, en la página principal puedo ller esto:

```
Para obtener la lista de usuarios autenticándote con un token, puedes usar:

curl -H "Authorization: Bearer password_secreta" http://localhost:5000/api/directorio_oculto
```

y me creo un script
