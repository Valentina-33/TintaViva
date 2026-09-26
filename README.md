# TintaViva

Estudio de tatuajes y galeria de arte inspirado en el simbolismo mexicano
(catrinas, flores de cempasuchil, alebrijes, arte tradicional). Aplicacion
web pequena hecha en Python + Flask para el **Laboratorio 04 - Auditoria de
Sistemas & DevSecOps (EX.04 y EX.05)**.

## Advertencia

Este repositorio contiene **fallas de seguridad plantadas a proposito**. El
objetivo es que una herramienta de analisis estatico (SAST), como Snyk o
SonarCloud, las detecte, y que el equipo practique el triage y la
remediacion de hallazgos reales. **No usar este codigo como base para un
proyecto real ni copiar sus patrones.**

## Que hace la app

- `/` - pagina de inicio del estudio.
- `/portafolio` - galeria de disenos, con buscador por estilo o artista.
- `/registro` y `/login` - registro e inicio de sesion de clientes.
- `/agendar` - agenda una cita para un diseno y genera un comprobante.
- `/referencia/<archivo>` - muestra una foto de referencia subida por un cliente.

## Como correrla

```bash
pip install -r requirements.txt
python3 init_db.py     # crea tintaviva.db con datos de ejemplo
python3 app.py          # http://localhost:5000
```

## Fallas plantadas (baseline `v0-vulnerable`)

Cada una esta marcada en el codigo con un comentario `VULN-N`.

| # | Vulnerabilidad | CWE | OWASP Top 10 (2021) | Archivo : linea |
|---|---|---|---|---|
| 1 | Inyeccion SQL por concatenacion de strings en el buscador del portafolio | CWE-89 | A03:2021 - Injection | `app.py:67` (comentario en `app.py:59`) |
| 2 | Inyeccion de comandos del sistema operativo al generar el comprobante de cita | CWE-78 | A03:2021 - Injection | `app.py:160` (comentario en `app.py:151`) |
| 3 | Secreto / API key quemada directamente en el codigo fuente | CWE-798 | A05:2021 - Security Misconfiguration | `app.py:33` (comentario en `app.py:25`) |
| 4 | Hash debil (MD5) y sin salt para almacenar contrasenas | CWE-916 | A02:2021 - Cryptographic Failures | `app.py:92` y `app.py:112` (tambien en `init_db.py:76`) |
| 5 | Dependencia con version antigua fijada, con CVEs publicos conocidos (Pillow 8.1.0) | CWE-1104 | A06:2021 - Vulnerable and Outdated Components | `requirements.txt` |
| 6 | Path traversal en el endpoint de lectura de fotos de referencia | CWE-22 | A01:2021 - Broken Access Control | `app.py:198` (comentario en `app.py:190`) |

### Detalle de cada hallazgo

**1. SQL Injection (`app.py:67`)**
La busqueda del portafolio arma la consulta concatenando directamente el
texto escrito por el usuario, sin usar parametros preparados. Ejemplo de
carga util:
```
' UNION SELECT id, correo, password_hash, 1, 1 FROM usuarios--
```

**2. OS Command Injection (`app.py:160`)**
El nombre del cliente se inserta sin escapar dentro de un comando de shell
(`os.system`) que genera el comprobante de la cita. Ejemplo de carga util
en el campo "Tu nombre":
```
Ana; rm -rf comprobantes; echo listo
```

**3. Secreto quemado en el codigo (`app.py:33`)**
La API key del servicio de notificaciones esta escrita en texto plano en
el codigo fuente. Queda expuesta a cualquiera con acceso al repositorio, y
persiste en el historial de git aunque se borre despues.

**4. Hash debil de contrasenas (`app.py:92`, `app.py:112`, `init_db.py:76`)**
Las contrasenas se almacenan con MD5 sin salt, un algoritmo rapido de
calcular y facilmente reversible con fuerza bruta en GPU o tablas rainbow.

**5. Dependencia desactualizada (`requirements.txt`)**
`Pillow==8.1.0` esta fijado a proposito; tiene multiples CVEs publicos
corregidos en versiones posteriores.

**6. Path Traversal (`app.py:198`)**
El endpoint `/referencia/<archivo>` concatena el nombre de archivo recibido
por la URL sin normalizar ni validar que se quede dentro de la carpeta de
referencias. Ejemplo de carga util:
```
/referencia/../../../../etc/passwd
```

## Estado del repositorio

- **Tag `v0-vulnerable`**: baseline con las 6 fallas descritas arriba, sin
  ninguna correccion. Este es el estado que se analiza con la herramienta
  SAST en el EX.05.
- Las correcciones posteriores (EX.05) se documentan en commits separados,
  referenciados desde el informe tecnico del laboratorio.
