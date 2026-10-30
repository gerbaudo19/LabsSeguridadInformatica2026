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
- **Alcance de la asistencia:** Asistencia en la inicialización de la entrega, estructuración del informe técnico, configuración del entorno de documentación para el grupo y registro de captura de banderas del CTF.
- **Partes originadas o modificadas:** Inicialización de `INTEGRANTES.md`, Sección 0 (Declaración de uso de IA) y Sección 1 (Flags capturadas de R1 a R5) de `informe.md`.
- **Verificación humana:** Se verificaron las credenciales y roles de los integrantes del Grupo 12, se validó la sintaxis y codificación de los archivos markdown, y se contrastaron los identificadores y hashes de los retos R1 a R5 contra `retos.manifest` y el servidor objetivo `phantomcorp`.

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
| SQLi auth (R1) | | | | |
| SQLi UNION (R2) | | | | |
| Command injection (R3) | | | | |
| Path traversal (R4) | | | | |
| IDOR (R5) | | | | |

---

## 3. Preguntas de análisis

**P1 — por qué funciona el bypass (con la query).**

**P2 — por qué el UNION necesita igual número de columnas.**

**P3 — qué sigue después del RCE.**

**P4 — por qué parametrizar mata la SQLi.**

**P5 — dónde va el control de acceso (IDOR).**

---

## 4. Bitácora de comandos

```bash
# curl -s -X POST http://phantomcorp/login --data-urlencode "user=..." ...
```
