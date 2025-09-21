import subprocess
import sys
import os

def ejecutar_script(nombre_script):
    """Ejecuta un script de Python y maneja los errores."""
    try:
        print(f"\n--- Ejecutando: {nombre_script} ---")
        # Usamos sys.executable para asegurarnos de usar el mismo intérprete de Python
        resultado = subprocess.run(
            [sys.executable, nombre_script],
            check=True,        # Lanza una excepción si el script falla
            capture_output=True, # Captura la salida
            text=True,         # Decodifica la salida como texto
            encoding='utf-8',  # Especifica la codificación para la salida
            errors='replace'   # Reemplaza caracteres malformados en lugar de fallar
        )
        print(resultado.stdout)
        print(f"--- OK: Finalizado {nombre_script} ---")
        return True
    except FileNotFoundError:
        print(f"ERROR: No se encontró el script '{nombre_script}'. Asegúrate de que esté en la misma carpeta.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"ERROR al ejecutar '{nombre_script}':")
        print(e.stderr) # Imprime el error que arrojó el script
        return False

print("==> Iniciando proceso completo de lectura y registro de DNIe...")

CERT_FILE = "cert_auth_clean.cer"

if ejecutar_script("Extraer_certificado.py") and os.path.exists(CERT_FILE):
    print(f"INFO: Archivo '{CERT_FILE}' creado correctamente.")
    
    if ejecutar_script("decodificar.py"):
        print("\n>> ¡Proceso completado exitosamente!")
        # Limpiar el archivo de certificado después de una inserción exitosa.
        os.remove(CERT_FILE)
        print(f"INFO: Se limpió el archivo temporal '{CERT_FILE}'.")
    else:
        print("\n>> Falló la decodificación o inserción en la base de datos.")
else:
    # Este bloque se ejecuta si la extracción falló O si el archivo no se creó.
    if not os.path.exists(CERT_FILE):
        print(f"ERROR: El script de extracción finalizó pero no generó el archivo '{CERT_FILE}'.")
    
    print("\n>> Proceso detenido debido a un fallo en la extracción del certificado.")