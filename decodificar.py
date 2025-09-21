# decodificar_dnie_final_lugar.py
# Extrae apellido, nombre, DNI y lugar desde un certificado DER del DNIe peruano

from insertar_db import conectar_db, insertar_persona
import re

def extract_utf8strings(data):
    """
    Devuelve todos los UTF8STRING del DER como lista de strings
    """
    results = []
    i = 0
    while i < len(data):
        if data[i] == 0x0c:  # Tag UTF8STRING
            length = data[i+1]
            string_bytes = data[i+2:i+2+length]
            try:
                results.append(string_bytes.decode("utf-8").strip())
            except UnicodeDecodeError:
                pass
            i += 2 + length
        else:
            i += 1
    return results

# Patrones
letter_pattern = re.compile(r"^[A-ZÑÁÉÍÓÚ\s\-]+$", re.IGNORECASE)
dni_pattern = re.compile(r"\b\d{8}\b")

with open("cert_auth_clean.cer", "rb") as f:
    cert_bytes = f.read()

utf8strings = extract_utf8strings(cert_bytes)

# Campos que corresponden al emisor y que se deben saltar
skip_keywords = ["Registro", "RENIEC", "CA Class"]

# Filtrar UTF8STRING válidos ignorando emisor
filtered_strings = [s for s in utf8strings if not any(k.lower() in s.lower() for k in skip_keywords)]

apellido = nombre = dni = lugar = None

# Heurística: buscar lugar primero, luego apellido, luego nombre
# Por observación del asn1parse:
# 1. localityName -> lugar
# 2. surname -> apellido
# 3. givenName -> nombre

# Buscar lugar: primer UTF8STRING que no sea emisor y contenga espacios (localityName)
for s in filtered_strings:
    if letter_pattern.match(s) and lugar is None:
        lugar = s
        continue
    # Primer string válido después del lugar es apellido
    if lugar is not None and apellido is None and letter_pattern.match(s):
        apellido = s
        continue
    # Segundo string válido después del lugar es nombre
    if lugar is not None and apellido is not None and nombre is None and letter_pattern.match(s):
        nombre = s

# Buscar DNI en cualquier UTF8STRING
for s in utf8strings:
    m = dni_pattern.search(s)
    if m:
        dni = m.group()
        break

print("Lugar:", lugar)
print("Apellido:", apellido)
print("Nombre:", nombre)
print("DNI:", dni)

# --- INICIO: Bloque para insertar en la base de datos ---

# 1. Conectar a la base de datos
db_connection = conectar_db()

# 2. Si la conexión es exitosa y tenemos todos los datos, los insertamos
if db_connection and all([apellido, nombre, dni, lugar]):
    insertar_persona(db_connection, apellido, nombre, dni, lugar)
    db_connection.close() # Cerramos la conexión al finalizar
    print("INFO: Conexión a la base de datos cerrada.")
