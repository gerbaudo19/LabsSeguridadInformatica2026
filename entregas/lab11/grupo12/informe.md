# Informe forense — Incidente PhantomCorp (phantomcorp-web)

**Grupo:** 12 · **Investigadores:** Mateo Gerbaudo (@gerbaudo19), Matias Mariatti (@matiasmariatticasc), Luis Alvaro Colque Condo (@ColqueAlvaro), Gonzalo Rodriguez (@Gonza149) · **Fecha:** 30 de Octubre de 2026  
**Sistema afectado:** phantomcorp-web (10.0.0.5) · **Tipo:** intrusión web + escalada de privilegios + exfiltración de base de datos  

---

## 0. Declaración de uso de IA

En conformidad con las directrices éticas de la cátedra, declaramos el uso de modelos de lenguaje (LLM) como asistentes analíticos en tareas de procesamiento de texto, correlación sintáctica y verificación cruzada de evidencias. Toda la reconstrucción pericial, extracción de artefactos volátiles y en disco, verificación criptográfica de hashes de custodia y deducción de la cadena de compromiso fue validada y respaldada por los investigadores del Grupo 12 sobre la evidencia forense cruda.

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

*(Sección a completar por Matías Mariatti en Commit 2)*

| Hora (UTC) | Evento | Evidencia (archivo:línea) |
|---|---|---|
| 02:14:02 | Reconocimiento inicial y escaneo web | `access.log:1-15` |
| | ... | |

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
