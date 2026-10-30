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
- **Alcance de la asistencia:** Inicialización y estructuración del entregable del grupo, configuración del archivo de integrantes, declaración formal de metodología de agentes de IA y registro estructurado de las banderas obtenidas en el CTF (@ColqueAlvaro — Commit 1).
- **Partes originadas o modificadas:** Inicialización de `INTEGRANTES.md`, Sección 0 (Declaración de uso de IA) y Sección 1 (Flags capturadas de R1 a R5) por @ColqueAlvaro; Sección 2 (Agente esqueleto completado y ejecución) a completar por @Gonza149; Sección 3 (Auditoría crítica del agente y guardrails) a completar por @gerbaudo19; Sección 4 (Preguntas de análisis P1–P5) y `research.md` a completar por @matiasmariatticasc.
- **Verificación humana:** Se validó que las 5 banderas correspondan a los hashes criptográficos verificados en `retos.manifest`. Se inspeccionó el mecanismo de guardrail de alcance en `src/herramientas.py` (`_verificar_alcance`) para constatar que bloquea determinísticamente cualquier intento de contacto con hosts fuera de `ALCANCE = {"phantomcorp"}`. En este laboratorio sobre agentes de inteligencia artificial, declarar el uso de IA es tanto un imperativo académico como una demostración de la práctica profesional de auditoría y gobierno sobre modelos autónomos.

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

*(A completar por @Gonza149 — Commit 2: Adjuntar `src/agente_esqueleto.py` completado y pegar la salida del agente capturando R5).*

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
