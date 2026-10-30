# Informe — Laboratorio 10 · Detección y evasión

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
- **Alcance de la asistencia:** Asistencia en la inicialización de la entrega, estructuración de las plantillas del informe técnico pericial, registro de la captura de banderas del CTF (R1–R5) y redacción técnica de la bitácora de comandos con eventos generados (@matiasmariatticasc).
- **Partes originadas o modificadas:** Inicialización de `INTEGRANTES.md`, Sección 0 (Declaración de uso de IA), Sección 1 (Flags capturadas de R1 a R5) y Sección 4 (Bitácora de comandos) por @matiasmariatticasc; Sección 2 (Tabla comparativa de firmas, técnicas de evasión y mejoras defensivas del Blue Team) por @ColqueAlvaro; Sección 3 (Preguntas de análisis P1-P5) y `research.md` a completar por @Gonza149 y @gerbaudo19.
- **Verificación humana:** Se validó la coherencia de los retos R1 a R5 contra `retos.manifest` y el servidor `phantomcorp-soc`. Matías Mariatti verificó los comandos curl ejecutados, comprobando los códigos de respuesta HTTP (403 Forbidden para alertas del IDS y 200 OK para evasiones), contrastando las firmas activas del ruleset y validando la detección en los logs del SOC.

---

## 1. Flags capturadas

Salida de `./ctf status 10`:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 10                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Acceso a la consola del SOC (/soc)
   ✓  R2     Deteccion disparada por User-Agent
   ✓  R3     Inspeccion del ruleset de firmas (/soc/reglas)
   ✓  R4     Evasion de firma sqli-union con ofuscacion
   ✓  R5     Identificacion de intrusion real en logs del SOC

  ██████████████████████████████  5/5 (100%)

  ✓ ¡Lab 10 COMPLETO! Ponete las pilas con la próxima unidad.
```

### Detalle de retos resueltos y flags obtenidas

| Reto | Perspectiva | Técnica empleada | Comando de descubrimiento | Flag capturada |
|---|---|---|---|---|
| **R1** | Blue Team | Acceso y visualización de eventos en consola SOC | `curl -s http://phantomcorp/soc` | `FLAG{soc_log_access}` |
| **R2** | Red Team | Generación de alerta intencional por User-Agent conocido | `curl -s -A sqlmap http://phantomcorp/` | `FLAG{detection_triggered}` |
| **R3** | Blue Team | Extracción y auditoría del ruleset activo de firmas IDS | `curl -s http://phantomcorp/soc/reglas` | `FLAG{signature_ruleset}` |
| **R4** | Red Team | Evasión de firma mediante comentario SQL inline (`/**/`) | `curl -s "http://phantomcorp/api?q=union/**/select"` | `FLAG{signature_evaded}` |
| **R5** | Blue Team | Filtrado y triaje de logs identificando intrusión ajena no atribuida | `curl -s http://phantomcorp/soc \| grep ALERT` | `FLAG{intrusion_in_the_noise}` |

---

## 2. Tabla de firmas

A continuación se analizan en profundidad las cuatro firmas del ruleset del IDS/WAF (`/soc/reglas`), detallando la técnica de evasión empleada (perspectiva Red Team) y las medidas de endurecimiento estructural necesarias para neutralizar los falsos negativos (perspectiva Blue Team):

| Firma | Patrón detectado en el IDS | Cómo la evadiste (o cómo se evade) | Cómo la mejorarías (Defensa / Blue Team) |
|---|---|---|---|
| **scanner-ua** | Expresión regular sobre la cabecera HTTP: `re.search(r"sqlmap\|nikto\|nmap\|dirb", ua, re.I)`. | **Modificación del encabezado User-Agent:** El User-Agent es un metadato controlado al 100% por el cliente. Para evadir la firma, se instruye a la herramienta a utilizar una cadena de User-Agent que imite a un navegador legítimo (ej. en curl con `-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"` o en sqlmap con `--random-agent`). Al eliminarse la subcadena `sqlmap`, la firma no coincide y la petición pasa como tráfico ordinario. | 1. **Detección comportamental y límites de tasa (*Rate Limiting*):** No depender de strings declarativos; detectar patrones de ráfagas anómalas de peticiones por segundo/minuto por IP.<br>2. **Fingerprinting de TLS y HTTP (JA3 / JA4):** Los escáneres utilizan stacks de red propios (ej. librerías Python `requests`, Go o libcurl) cuyas firmas de apretón de manos TLS (ciphers, extensiones, orden de curvas elípticas) difieren totalmente de navegadores reales como Chrome o Firefox.<br>3. **Análisis de entropía y payloads en parámetros:** Inspeccionar el contenido del cuerpo y query string en lugar de los encabezados cosméticos. |
| **sqli-union** | Expresión regular: `re.search(r"union\s+select", q, re.I)`. Exige **uno o más caracteres de espacio** (`\s+`) entre `UNION` y `SELECT`. | **Reemplazo del espacio por comentarios SQL inline (`/**/`):** De acuerdo a la gramática SQL (especificación ANSI y motores como SQLite, MySQL o PostgreSQL), los comentarios multilínea `/**/` actúan como delimitadores sintácticos válidos equivalentes al espacio en blanco. Enviando `q=union/**/select` (o variantes como `UNION(SELECT...)`, tabulaciones `%09`, saltos de línea `%0A`, o comentarios de versión `/*!50000UNION*//*!50000SELECT*/`), el motor de base de datos ejecuta la inyección normalmente, pero la regex del IDS falla al no hallar el espacio literal esperado. | 1. **Normalización y sanitización canónica previa:** El WAF debe procesar la entrada eliminando comentarios (`/\*.*?\*/`), resolviendo encodings recursivos y normalizando espacios en blanco antes de evaluar cualquier regla.<br>2. **Inspección semántica basada en AST (*Abstract Syntax Tree*):** Utilizar analizadores sintácticos reales de SQL como **libinjection** en lugar de expresiones regulares estáticas. Libinjection tokeniza la sentencia como un compilador real, detectando la estructura relacional anómala sin importar ofuscaciones.<br>3. **Consultas preparadas (Prepared Statements):** Parametrizar en el backend con placeholders (`?`), haciendo imposible la inyección a nivel de código. |
| **path-traversal** | Búsqueda estática lineal de subcadena: `"../" in path or "../" in q`. | **Ofuscación de secuencias de escape de directorio:**<br>1. *Doble URL encoding:* `%252e%252e%252f` (si el backend decodifica dos veces y el WAF una sola).<br>2. *Secuencias anidadas de auto-eliminación:* `....//` o `..././` (si el filtro elimina `../` de forma no recursiva, al borrar el bloque central se reconstituye el `../`).<br>3. *Separadores alternativos de ruta:* En servidores Windows o entornos heterogéneos, uso de barras invertidas (`..\` o `%5c%2e%2e%5c`).<br>4. *Encoding Unicode/Overlong:* `%c0%ae%c0%ae%c0%af`. | 1. **Resolución de ruta canónica previa en el WAF:** Decodificar de forma exhaustiva y resolver la ruta absoluta canónica antes de comparar con las firmas.<br>2. **Validación estricta en el servidor web / aplicación:** Resolver la ruta canónica en código mediante llamadas de bajo nivel (`os.path.realpath()`) y verificar obligatoriamente que comience con el prefijo del directorio base autorizado (`commonpath`), rechazando cualquier petición que intente escapar de la raíz pública. |
| **git-probe** | Coincidencia estática de subcadena: `"/.git" in path`. | **Variaciones de codificación y rutas redundantes:**<br>1. *URL-encoding parcial:* `/%2e%67%69%74` o `/.%67it`.<br>2. *Inyección de directorios relativos superfluos:* `/app/./.git/` o `/app/dummy/../.git/`.<br>3. *Variaciones de mayúsculas/minúsculas:* `/.GIT/config` en sistemas de archivos *case-insensitive*.<br>4. *Peticiones directas a archivos internos:* Consultar objetos directamente vía `/.git/objects/...` o ramas en `/.git/refs/heads/master`. | 1. **Bloqueo global en servidor web (Nginx/Apache):** Implementar una regla genérica y robusta en el servidor HTTP que bloquee el acceso a cualquier archivo o directorio oculto que comience con un punto (`location ~ /\. { deny all; return 404; }`), eliminando la dependencia de firmas en el WAF.<br>2. **Normalización integral de la URI en el motor de detección:** Aplicar transformaciones canónicas de minúsculas (`lowercase`), resolución de `.` y `..`, y decodificación completa antes de cotejar contra la lista negra. |

---

## 3. Preguntas de análisis (P1–P5)

*(A completar por Gonzalo Rodríguez y Mateo Gerbaudo en Commits 3 y 4)*

---

## 4. Bitácora de comandos

Comandos ejecutados desde la consola del atacante (`make shell`) contra el entorno monitoreado `http://phantomcorp`:

```bash
# ==========================================
# R1: Acceso a la consola del SOC (Blue Team)
# ==========================================
# Inspección inicial del endpoint del SOC y visor de eventos
curl -s http://phantomcorp/soc | head -n 15

# Enviar flag R1 al evaluador CTF
./ctf submit 10 R1 'FLAG{soc_log_access}'

# ==========================================
# R2: Provocar detección intencional (Red Team)
# ==========================================
# Envío de User-Agent clasificado como escáner en firmas (sqlmap)
# Respuesta esperada: HTTP 403 Forbidden con alerta del IDS
curl -i -s -A sqlmap http://phantomcorp/

# Enviar flag R2 al evaluador CTF
./ctf submit 10 R2 'FLAG{detection_triggered}'

# ==========================================
# R3: Auditoría del Ruleset de Firmas (Blue Team)
# ==========================================
# Consulta de las reglas y expresiones regulares activas en el IDS
curl -s http://phantomcorp/soc/reglas

# Enviar flag R3 al evaluador CTF
./ctf submit 10 R3 'FLAG{signature_ruleset}'

# ==========================================
# R4: Evasión de Firma sqli-union (Red Team)
# ==========================================
# La regla exige 'union\\s+select' con espacio. Se reemplaza el espacio por un comentario SQL inline:
# Petición enviada: /api?q=union/**/select
# Respuesta esperada: HTTP 200 OK (bypass exitoso, no detectado por IDS)
curl -s "http://phantomcorp/api?q=union/**/select"

# Enviar flag R4 al evaluador CTF
./ctf submit 10 R4 'FLAG{signature_evaded}'

# ==========================================
# R5: Correlación e Identificación de Intrusión (Blue Team)
# ==========================================
# Filtrado de eventos de alerta en los logs del SOC para aislar la intrusión externa (IP 185.220.101.42)
curl -s http://phantomcorp/soc | grep ALERT

# Enviar flag R5 al evaluador CTF
./ctf submit 10 R5 'FLAG{intrusion_in_the_noise}'

# ==========================================
# Verificación de estado del laboratorio
# ==========================================
./ctf status 10
```
