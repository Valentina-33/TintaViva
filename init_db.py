"""
init_db.py
Crea la base de datos SQLite de TintaViva y la llena con datos de ejemplo:
disenos de tatuaje inspirados en arte y simbolismo mexicano, artistas del
estudio, y un usuario cliente de prueba.

Correr una sola vez antes de levantar la app:
    python3 init_db.py
"""

import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = "tintaviva.db"


def crear_base_datos():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS usuarios")
    cur.execute("DROP TABLE IF EXISTS disenos")
    cur.execute("DROP TABLE IF EXISTS citas")

    cur.execute(
        """
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            correo TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE disenos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            estilo TEXT NOT NULL,
            artista TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            precio_base INTEGER NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE citas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_nombre TEXT NOT NULL,
            diseno_id INTEGER,
            fecha TEXT NOT NULL,
            referencia_archivo TEXT
        )
        """
    )

    # --- Disenos de ejemplo, inspirados en arte y simbolismo mexicano ---
    disenos = [
        ("La Catrina Elegante", "fine-line", "Keyla", "Catrina clasica en linea fina con detalles florales en el sombrero.", 350000),
        ("Flor de Cempasuchil", "acuarela", "Keyla", "Cempasuchil en tecnica de acuarela, colores calidos degradados.", 220000),
        ("Alebrije Alado", "neotradicional", "Mariana", "Alebrije fantastico con alas de mariposa monarca, colores saturados.", 400000),
        ("Corazon Sagrado", "blackwork", "Diego", "Sagrado corazon con ornamentos geometricos en blackwork solido.", 280000),
        ("Nopal y Serpiente", "tradicional mexicano", "Mariana", "Escena inspirada en el escudo nacional, estilo tradicional con sombreado.", 380000),
        ("Papel Picado", "linea fina", "Keyla", "Patron de papel picado enmarcando una frase corta a eleccion del cliente.", 190000),
    ]
    cur.executemany(
        "INSERT INTO disenos (nombre, estilo, artista, descripcion, precio_base) VALUES (?, ?, ?, ?, ?)",
        disenos,
    )

    # --- Usuario cliente de prueba ---
    # VULN-4 (CWE-916 - Uso de un algoritmo de hash debil para contrasenas)
    # Se usa MD5 para almacenar la contrasena. MD5 es rapido de calcular y
    # facilmente reversible con tablas rainbow / fuerza bruta con GPU,
    # por lo que no es apto para proteger credenciales.
    password_demo = "flordemayo123"
    password_hash = generate_password_hash(password_demo)

    cur.execute(
        "INSERT INTO usuarios (nombre, correo, password_hash) VALUES (?, ?, ?)",
        ("Cliente Demo", "cliente@correo.com", password_hash),
    )

    conn.commit()
    conn.close()
    print(f"Base de datos '{DB_NAME}' creada con datos de ejemplo.")
    print(f"Usuario demo -> correo: cliente@correo.com | password: {password_demo}")


if __name__ == "__main__":
    crear_base_datos()
