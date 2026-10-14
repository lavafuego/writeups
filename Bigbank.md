## FASE DE RECONOCIMIENTO
desplegamos la máquina y sabiendo que su IP es `172.17.0.2 ` vamos a realizar un escaneo de puertos para ver cuales tiene abiertos, los servicios que corren
por ello y las versiones por si son vulnerables:

```bash
sudo nmap -sS -sVC -p- --open -Pn --min-rate 5000 -vvv 172.17.0.2 -oN PuertosYServicios
```
![CTF](images/bigbank/1.png)
