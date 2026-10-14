## FASE DE RECONOCIMIENTO
desplegamos la máquina y sabiendo que su IP es `172.17.0.2 ` vamos a realizar un escaneo de puertos para ver cuales tiene abiertos, los servicios que corren
por ello y las versiones por si son vulnerables:

```bash
sudo nmap -sS -sVC -p- --open -Pn --min-rate 5000 -vvv 172.17.0.2 -oN PuertosYServicios
```
![CTF](images/bigbank/1.png)


![CTF](images/bigbank/2.png)



Vemos:

-Puerto 22, SSH con version no vulnerable a enumeracion de usuarios


-Puerto 80, HTTP


Nos vamos a centrar en el puerto 80:

```bash
whatweb http://172.17.0.2 | tee whatweb

curl -I 172.17.0.2 
```

![CTF](images/bigbank/3.png)


No vvemos nada rao así pues abrimos la página en el navegador:




![CTF](images/bigbank/4.png)



Vemos que pone autenticacion JWT, y mirando el código fuente vemos una ruta interesante:

```
/api/v1/_docs-3fcb199bbb">Documentación de la API 
```


![CTF](images/bigbank/5.png)

