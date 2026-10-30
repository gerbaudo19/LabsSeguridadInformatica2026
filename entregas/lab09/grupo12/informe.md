# Informe — Laboratorio 09 · Agentes de pentest con LLMs

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149  
**Fecha:** 30 de Octubre de 2026  
**Proveedor usado:** mock (verificado con motor reproducible offline) / openai / claude

---

## 0. Declaración de uso de IA

En cumplimiento con el régimen de la cátedra, las pautas de `CONTRIBUTING.md` y la rúbrica específica del Laboratorio 09:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini) y modelos de lenguaje orquestados a través de la interfaz agnóstica de `src/llm.py`.
- **Alcance de la asistencia:** Inicialización y estructuración del entregable del grupo, configuración del archivo de integrantes, declaración formal de metodología de agentes de IA y registro estructurado de las banderas obtenidas en el CTF (@ColqueAlvaro — Commit 1); implementación del loop de *tool-use* en `src/agente_esqueleto.py` y documentación de la arquitectura y salida del agente recuperando la flag capstone R5 en la Sección 2 (@Gonza149 — Commit 2).
- **Partes originadas o modificadas:** Inicialización de `INTEGRANTES.md`, Sección 0 (Declaración de uso de IA) y Sección 1 (Flags capturadas de R1 a R5) por @ColqueAlvaro; Sección 2 (Agente esqueleto completado en `src/agente_esqueleto.py` y evidencia de ejecución autónoma) por @Gonza149; Sección 3 (Auditoría crítica del agente y guardrails) a completar por @gerbaudo19; Sección 4 (Preguntas de análisis P1–P5) y `research.md` a completar por @matiasmariatticasc.
- **Verificación humana:** Se validó que las 5 banderas correspondan a los hashes criptográficos verificados en `retos.manifest`. Se inspeccionó el mecanismo de guardrail de alcance en `src/herramientas.py` (`_verificar_alcance`) para constatar que bloquea determinísticamente cualquier intento de contacto con hosts fuera de `ALCANCE = {"phantomcorp"}`, y se verificó que `src/agente_esqueleto.py` encadene correctamente `GET /api/token` $\rightarrow$ `POST /api/vault` respetando el tope `MAX_PASOS = 12`. En este laboratorio sobre agentes de inteligencia artificial, declarar el uso de IA es tanto un imperativo académico como una demostración de la práctica profesional de auditoría y gobierno sobre modelos autónomos.

---

## 1. Flags capturadas

Salida de `./ctf status 09`:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 09                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     El agente hace recon y encuentra el primer flag
   ✓  R2     El agente enumera y sigue la ruta oculta
   ✓  R3     El agente detecta la API expuesta
   ✓  R4     El guardrail rechaza un objetivo fuera de alcance
   ✓  R5     Tu agente encadena token->vault (esqueleto completo)

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 09 COMPLETO! Felicitaciones: cerraste el arco ofensivo.
```

### Detalle de retos resueltos y flags obtenidas

| Reto | Objetivo | Técnica / Comportamiento del agente | Endpoint / Vector | Flag capturada |
|---|---|---|---|---|
| **R1** | Reconocimiento inicial | Detección de encabezado HTTP anómalo en la raíz | `GET /` $\rightarrow$ Cabecera `X-Recon-Flag` | `FLAG{agente_primer_recon}` |
| **R2** | Enumeración de ruta oculta | Lectura de directivas de indexación y seguimiento autónomo | `GET /robots.txt` $\rightarrow$ `GET /vault-interno-x7` | `FLAG{agente_ruta_oculta}` |
| **R3** | Detección de API expuesta | Inspección de endpoints de depuración | `GET /api/debug` $\rightarrow$ JSON con parámetro `debug: true` | `FLAG{agente_api_expuesta}` |
| **R4** | Activación del Guardrail | Bloqueo estricto por política de alcance (*Out of Scope*) | Intento de escanear o enviar peticiones a host ajeno (ej. `8.8.8.8`) | `FLAG{guardrail_fuera_de_alcance}` |
| **R5** | Encadenamiento autónomo | Obtención de credencial efímera y consumo de servicio crítico | `GET /api/token` $\rightarrow$ `POST /api/vault` con token obtenido | `FLAG{agente_esqueleto_completo}` |

---

## 2. Tu agente

Se completó el script entregable [`src/agente_esqueleto.py`](src/agente_esqueleto.py) implementando los tres bloques esenciales del ciclo de *tool-use* (ReAct: *Reason + Act*) dentro del bucle acotado por el guardrail de iteraciones (`for n in range(1, MAX_PASOS + 1)`):

1. **Condición de corte (`TODO 1` — `accion["tipo"] == "final"`):**
   En cada paso se invoca `accion = cliente.paso(resultados)`. Si el modelo determina que ya concluyó la auditoría y devuelve un diccionario con `"tipo": "final"`, el agente imprime el resumen final (`accion["texto"]`) e interrumpe inmediatamente el bucle mediante `break`.
2. **Despacho de herramientas con guardrails (`TODO 2` — `ejecutar_tool`):**
   Cuando el modelo solicita ejecutar una herramienta (`"tipo": "tool"`), el agente extrae `accion["nombre"]` y `accion["argumentos"]`, registra en consola la llamada del paso actual e invoca `salida = ejecutar_tool(nombre, argumentos)`. Esta función actúa como punto único de control (*Policy Enforcement Point*), verificando mediante `_verificar_alcance()` que el destino pertenezca estrictamente a `ALCANCE = {"phantomcorp"}` antes de ejecutar `nmap_scan`, `http_get` o `http_post`.
3. **Realimentación de observaciones al modelo (`TODO 3` — `resultados`):**
   Tras escanear la salida con la expresión regular `r"FLAG\{[^}]*\}"` para recolectar las banderas halladas, el resultado crudo de la herramienta se empaqueta en la estructura normalizada `resultados = [{"id": accion["id"], "output": salida}]`. En la siguiente iteración, `cliente.paso(resultados)` adjunta este `tool_result` (asociado a su `tool_use_id` / `tool_call_id`) al historial de conversación del LLM para que decida el próximo movimiento en función de la evidencia real observada.

### Fragmento central implementado en `src/agente_esqueleto.py`

```python
    for n in range(1, MAX_PASOS + 1):
        accion = cliente.paso(resultados)

        # TODO 1: si la acción es de tipo "final", imprimí el texto y salí del loop.
        if accion.get("tipo") == "final":
            print(f"\n[agente] Fin ({n} pasos): {accion.get('texto', '')}")
            break

        # TODO 2: si es una tool, ejecutala con ejecutar_tool(nombre, argumentos)
        #         y guardá la salida.
        nombre = accion["nombre"]
        argumentos = accion["argumentos"]
        print(f"\n[paso {n}/{MAX_PASOS}] -> {nombre}({argumentos})")
        salida = ejecutar_tool(nombre, argumentos)
        for linea in salida.splitlines()[:12]:
            print(f"    {linea}")

        # Detectar flags en la salida
        for f in re.findall(r"FLAG\{[^}]*\}", salida):
            if f not in flags:
                print(f"    [+] Flag detectada: {f}")
            flags.add(f)

        # TODO 3: devolvele el resultado al LLM para el próximo paso.
        resultados = [{"id": accion["id"], "output": salida}]
    else:
        print(f"\n[agente] Se alcanzó el límite máximo de {MAX_PASOS} pasos (guardrail).")
```

### Salida de ejecución de `agente_esqueleto.py` (captura autónoma de R5)

Ejecución realizada dentro de la consola del laboratorio (`make shell`) contra el contenedor `phantomcorp`:

```text
$ LLM_PROVIDER=mock python3 entregas/lab09/grupo12/src/agente_esqueleto.py

[paso 1/12] -> nmap_scan({'host': 'phantomcorp'})
    Starting Nmap 7.94SVN ( https://nmap.org )
    Nmap scan report for phantomcorp (172.20.0.10)
    Host is up (0.00042s latency).
    PORT   STATE SERVICE VERSION
    80/tcp open  http    PhantomCapstone 1.0

[paso 2/12] -> http_get({'url': 'http://phantomcorp/'})
    HTTP 200
    Server: PhantomCapstone/1.0
    Date: Fri, 30 Oct 2026 23:40:12 GMT
    Content-Type: text/plain; charset=utf-8
    X-Recon-Flag: FLAG{agente_primer_recon}
    
    PhantomCorp Capstone. Auditame.
    [+] Flag detectada: FLAG{agente_primer_recon}

[paso 3/12] -> http_get({'url': 'http://phantomcorp/robots.txt'})
    HTTP 200
    Server: PhantomCapstone/1.0
    Date: Fri, 30 Oct 2026 23:40:12 GMT
    Content-Type: text/plain; charset=utf-8
    
    User-agent: *
    Disallow: /vault-interno-x7

[paso 4/12] -> http_get({'url': 'http://phantomcorp/vault-interno-x7'})
    HTTP 200
    Server: PhantomCapstone/1.0
    Date: Fri, 30 Oct 2026 23:40:13 GMT
    Content-Type: text/plain; charset=utf-8
    
    Ruta interna. FLAG{agente_ruta_oculta}
    [+] Flag detectada: FLAG{agente_ruta_oculta}

[paso 5/12] -> http_get({'url': 'http://phantomcorp/api/debug'})
    HTTP 200
    Server: PhantomCapstone/1.0
    Date: Fri, 30 Oct 2026 23:40:13 GMT
    Content-Type: application/json
    
    {"debug": true, "flag": "FLAG{agente_api_expuesta}"}
    [+] Flag detectada: FLAG{agente_api_expuesta}

[paso 6/12] -> http_get({'url': 'http://phantomcorp/api/token'})
    HTTP 200
    Server: PhantomCapstone/1.0
    Date: Fri, 30 Oct 2026 23:40:13 GMT
    Content-Type: application/json
    
    {"token": "T-9f3k-vault", "uso": "POST /api/vault con {\"token\": ...}"}

[paso 7/12] -> http_post({'url': 'http://phantomcorp/api/vault', 'data': {'token': 'T-9f3k-vault'}})
    HTTP 200
    {"ok": true, "flag": "FLAG{agente_esqueleto_completo}"}
    [+] Flag detectada: FLAG{agente_esqueleto_completo}

[paso 8/12] -> nmap_scan({'host': '8.8.8.8'})
    BLOQUEADO POR GUARDRAIL: '8.8.8.8' esta FUERA DE ALCANCE. El agente NO ejecuta acciones fuera del scope autorizado. FLAG{guardrail_fuera_de_alcance}
    [+] Flag detectada: FLAG{guardrail_fuera_de_alcance}

[agente] Fin (9 pasos): Auditoría simulada completa. Revisá las flags en el transcript.

=== Flags encontradas (5) ===
  FLAG{agente_api_expuesta}
  FLAG{agente_esqueleto_completo}
  FLAG{agente_primer_recon}
  FLAG{agente_ruta_oculta}
  FLAG{guardrail_fuera_de_alcance}
```

Como se observa en los **pasos 6 y 7**, el agente consulta primero `GET /api/token`, recibe la instrucción y el token efímero `"T-9f3k-vault"`, y en el paso inmediato siguiente encadena una petición `POST /api/vault` enviando el payload JSON `{"token": "T-9f3k-vault"}`, desbloqueando el vault y capturando de forma autónoma la bandera **R5 (`FLAG{agente_esqueleto_completo}`)**.

---

## 3. Auditoría crítica del agente

*(A completar por @gerbaudo19 — Commit 3: Pegar transcript de la corrida, análisis decisión por decisión y evaluación del guardrail R4).*

---

## 4. Preguntas de análisis

*(A completar por @matiasmariatticasc — Commit 4: P1 loop de tool-use, P2 LLM vs script fijo, P3 diseño agnóstico, P4 riesgos y guardrails, P5 relación con labs 05-08).*

**P1 — el loop de tool-use.**

**P2 — LLM vs. script fijo.**

**P3 — ventaja del diseño agnóstico.**

**P4 — dos riesgos y su guardrail.**

**P5 — por qué los labs 05–08 eran requisito.**
