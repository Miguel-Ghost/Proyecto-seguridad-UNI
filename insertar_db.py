# insertar_db.py
import psycopg2

def conectar_db():
    """
    Establece la conexión con la base de datos PostgreSQL.
    ¡Recuerda cambiar los parámetros de conexión!
    """
    try:
        conn = psycopg2.connect(
            dbname="seguridad_uni",
            user="postgres",
            password="123456789",
            host="localhost",  # o la IP de tu servidor de base de datos
            port="5432"
        )
        print("OK: Conexión a la base de datos PostgreSQL exitosa.")
        return conn
    except psycopg2.OperationalError as e:
        print(f"ERROR: No se pudo conectar a la base de datos: {e}")
        return None

def insertar_persona(conn, apellido, nombre, dni, lugar):
    """
    Inserta los datos de una persona en la tabla 'personas'.
    Utiliza parámetros para evitar inyección SQL.
    """
    if not conn:
        print("ERROR: No hay conexión a la base de datos para insertar.")
        return

    sql = """
        INSERT INTO personas (apellido, nombre, dni, lugar)
        VALUES (%s, %s, %s, %s);
    """
    try:
        with conn.cursor() as cur:
            # Ejecutar el comando SQL con los datos
            cur.execute(sql, (apellido, nombre, dni, lugar))
            # Confirmar la transacción
            conn.commit()
            print(f"OK: Datos insertados correctamente para DNI: {dni}")
    except Exception as e:
        print(f"ERROR: Error al insertar datos: {e}")
        conn.rollback() # Revertir la transacción en caso de error