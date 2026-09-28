"""
TintaViva - estudio de tatuajes y galeria de arte
Laboratorio 04 - EX.04 Beginner Vulnerable Repository Creation

Esta aplicacion se construyo A PROPOSITO con fallas de seguridad para que
una herramienta SAST (Snyk / SonarCloud) las detecte en el EX.05. Cada falla
esta marcada con un comentario "VULN-N" que indica su clase (CWE) y su
categoria OWASP correspondiente. NO usar este codigo como referencia de buenas
practicas: es precisamente lo contrario.

Uso academico - Laboratorio de Auditoria de Sistemas & DevSecOps.
"""

import os
import os
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "dev"

DB_NAME = "tintaviva.db"

# ---------------------------------------------------------------------------
# VULN-3 (CWE-798 - Uso de credenciales embebidas / secreto quemado en el codigo)
# OWASP A05:2021 - Security Misconfiguration / A02:2021 - Cryptographic Failures
# La API key del servicio de notificaciones (simulando un proveedor tipo
# Twilio/WhatsApp Business API) esta escrita directamente en el codigo fuente.
# Cualquiera con acceso al repositorio (o a este archivo) tiene la clave real.
# En un caso real, esta clave quedaria ademas en el historial de git para
# siempre, incluso si se borra despues de este commit.
# ---------------------------------------------------------------------------
NOTIFICACIONES_API_KEY = os.environ.get("NOTIFICACIONES_API_KEY", "")


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/portafolio")
def portafolio():
    """
    Galeria de disenos. Permite buscar por estilo o por artista usando el
    parametro ?q=... en la URL.
    """
    busqueda = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()

    if busqueda:
        # -----------------------------------------------------------------
        # VULN-1 (CWE-89 - SQL Injection)
        # OWASP A03:2021 - Injection
        # La consulta se arma concatenando directamente el texto que escribe
        # el usuario en el buscador, sin ningun tipo de sanitizacion ni uso
        # de parametros preparados (placeholders). Un valor como:
        #   ' UNION SELECT id, correo, password_hash, 1, 1 FROM usuarios--
        # permite extraer datos de otras tablas de la base de datos.
        # -----------------------------------------------------------------
        query = "SELECT * FROM disenos WHERE estilo LIKE ? OR artista LIKE ?"
        like = f"%{busqueda}%"
        cur.execute(query, (like, like))
    else:
        cur.execute("SELECT * FROM disenos")

    disenos = cur.fetchall()
    conn.close()
    return render_template("portafolio.html", disenos=disenos, busqueda=busqueda)


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"]
        correo = request.form["correo"]
        password = request.form["password"]

        # -------------------------------------------------------------
        # VULN-4 (CWE-916 - Uso de un algoritmo de hash debil / sin salt)
        # OWASP A02:2021 - Cryptographic Failures
        # MD5 es un algoritmo rapido y no esta disenado para contrasenas:
        # es trivial de romper con fuerza bruta en GPU o con tablas
        # rainbow. Deberia usarse un algoritmo lento y con salt como
        # bcrypt, scrypt o argon2.
        # -------------------------------------------------------------
        password_hash = generate_password_hash(password)

        conn = get_db()
        conn.execute(
            "INSERT INTO usuarios (nombre, correo, password_hash) VALUES (?, ?, ?)",
            (nombre, correo, password_hash),
        )
        conn.commit()
        conn.close()
        flash("Cuenta creada. Ya puedes agendar tu cita.")
        return redirect(url_for("login"))

    return render_template("registro.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form["correo"]
        password = request.form["password"]
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM usuarios WHERE correo = ?", (correo,))
        usuario = cur.fetchone()
        conn.close()

        if usuario and check_password_hash(usuario["password_hash"], password):
            flash(f"Bienvenida/o, {usuario['nombre']}.")
            return redirect(url_for("portafolio"))
        else:
            flash("Correo o contrasena incorrectos.")

    return render_template("login.html")


@app.route("/agendar", methods=["GET", "POST"])
def agendar():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM disenos")
    disenos = cur.fetchall()

    if request.method == "POST":
        cliente_nombre = request.form["cliente_nombre"]
        diseno_id = request.form["diseno_id"]
        fecha = request.form["fecha"]

        cur.execute(
            "INSERT INTO citas (cliente_nombre, diseno_id, fecha) VALUES (?, ?, ?)",
            (cliente_nombre, diseno_id, fecha),
        )
        conn.commit()

        # ---------------------------------------------------------------
        # VULN-2 (CWE-78 - OS Command Injection)
        # OWASP A03:2021 - Injection
        # Se genera un comprobante en texto plano usando el nombre del
        # cliente directamente dentro de un comando de shell, sin escapar
        # ni validar. Un nombre como:
        #   Ana; rm -rf /home/tintaviva/uploads; echo listo
        # permite ejecutar comandos arbitrarios en el servidor.
        # ---------------------------------------------------------------
        nombre_seguro = secure_filename(cliente_nombre) or "cliente"
        ruta_comprobante = os.path.join("comprobantes", f"comprobante_{nombre_seguro}.txt")
        with open(ruta_comprobante, "w", encoding="utf-8") as fh:
            fh.write(f"Cita confirmada para {cliente_nombre} el {fecha}\n")

        notificar_cliente_demo(cliente_nombre)

        conn.close()
        flash("Cita agendada. Te llegara un comprobante.")
        return redirect(url_for("agendar"))

    conn.close()
    return render_template("agendar.html", disenos=disenos)


def notificar_cliente_demo(nombre_cliente):
    """
    Simula el envio de una notificacion usando el servicio externo cuya
    API key esta quemada en el codigo (ver VULN-3, arriba del archivo).
    No hace una llamada de red real; es solo para ilustrar donde se
    usaria el secreto en un caso real.
    """
    print(f"[notificaciones] usando API key {NOTIFICACIONES_API_KEY[:12]}... "
          f"para notificar a {nombre_cliente}")


@app.route("/referencia/<path:nombre_archivo>")
def ver_referencia(nombre_archivo):
    """
    Muestra una foto de referencia que un cliente subio previamente para
    su diseno.
    """
    # -------------------------------------------------------------------
    # VULN-6 (CWE-22 - Path Traversal / Improper Limitation of a Pathname)
    # OWASP A01:2021 - Broken Access Control
    # El nombre de archivo que llega por la URL se concatena directamente
    # a la ruta base sin normalizar ni validar que se quede dentro de la
    # carpeta de referencias. Una peticion a:
    #   /referencia/../../../../etc/passwd
    # permite leer archivos arbitrarios del servidor.
    # -------------------------------------------------------------------
    return send_from_directory("static/referencias", nombre_archivo)


if __name__ == "__main__":
    os.makedirs("comprobantes", exist_ok=True)
    os.makedirs("static/referencias", exist_ok=True)
    if not os.path.exists(DB_NAME):
        print("No se encontro la base de datos. Corre primero: python3 init_db.py")
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, host="127.0.0.1", port=5000)
