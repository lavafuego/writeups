## FASE ENUMERACION

Sabiendo la IP de la máquina víctima vamos a hacer un reconocimiento de los puertos abiertos y los servicios
que corren por ellos, así como sus versiones para ver si tienen alguna vulnerabilidad:

IP-->`172.17.0.2`

```bash
 sudo nmap -sS -sCV -Pn --min-rate 5000 -p- -v --open 172.17.0.2 -oN puertosYservicios
```

![Nmap Scan](images/Waffy/1.png)
