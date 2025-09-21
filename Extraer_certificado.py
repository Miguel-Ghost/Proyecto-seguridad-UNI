import sys
from smartcard.System import readers
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Función para mostrar bytes en hexdump
def hexdump(data, length=16):
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_chunk = " ".join(f"{b:02X}" for b in chunk)
        ascii_chunk = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"{i:04X}: {hex_chunk:<48} {ascii_chunk}")

# Función para decodificar longitud ASN.1
def decode_asn1_length(data, offset):
    """Decodifica la longitud ASN.1 y retorna (longitud, bytes_consumidos)"""
    length_byte = data[offset]
    
    if length_byte & 0x80 == 0:
        # Forma corta: longitud en 1 byte
        return length_byte, 1
    else:
        # Forma larga: número de bytes que siguen
        num_length_bytes = length_byte & 0x7F
        if num_length_bytes == 0:
            raise ValueError("Longitud indefinida no soportada")
        if num_length_bytes > 4:
            raise ValueError(f"Longitud demasiado grande: {num_length_bytes} bytes")
        
        length = 0
        for i in range(num_length_bytes):
            length = (length << 8) | data[offset + 1 + i]
        
        return length, 1 + num_length_bytes

# Conexión a la tarjeta
r = readers()
if len(r) == 0:
    print("No hay lectores disponibles")
    exit()

connection = r[0].createConnection()
connection.connect()
print(f"==> Conectado al lector: {r[0]}")

# Paso 2: Seleccionar aplicación PKI
SELECT_PKI = [0x00, 0xA4, 0x04, 0x00, 0x0E] + [
    0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD2, 0x50,
    0x47, 0x65, 0x6E, 0x65, 0x72, 0x69, 0x63
]
response, sw1, sw2 = connection.transmit(SELECT_PKI)
if (sw1, sw2) != (0x90, 0x00):
    print(f"ERROR: No se pudo seleccionar PKI: {sw1:02X} {sw2:02X}")
    exit()
print("OK: Aplicacion PKI seleccionada")

# Paso 3: Seleccionar certificado de autenticación (File ID 00 1C)
SELECT_AUTH_CERT = [0x00, 0xA4, 0x02, 0x04, 0x02, 0x00, 0x1C]
response, sw1, sw2 = connection.transmit(SELECT_AUTH_CERT)
if (sw1, sw2) != (0x90, 0x00):
    print(f"ERROR: No se pudo seleccionar certificado: {sw1:02X} {sw2:02X}")
    exit()
print("OK: Certificado de autenticacion seleccionado")

# Paso 4: Leer TODO el certificado disponible
print("... Iniciando lectura completa del certificado...")
cert_data = bytearray()
offset = 0

# Leer TODOS los datos disponibles hasta EOF
while True:
    offset_high = (offset >> 8) & 0xFF
    offset_low = offset & 0xFF
    
    READ_BINARY_ENHANCED = [
        0x00, 0xB1, 0x00, 0x00,
        0x04, 0x54, 0x02, offset_high, offset_low, 
        0xFF
    ]
    
    try:
        chunk, sw1, sw2 = connection.transmit(READ_BINARY_ENHANCED)
        
        if (sw1, sw2) == (0x90, 0x00):
            if len(chunk) == 0:
                print("INFO: No hay mas datos (chunk vacio)")
                break
                
            cert_data.extend(chunk)
            offset += len(chunk)
            print(f"Leidos {len(chunk)} bytes, offset: {offset}, total: {len(cert_data)} bytes")
            
            # Continuar hasta que no haya más datos
            if len(chunk) < 255:
                print("INFO: Chunk parcial recibido, continuando...")
            
        elif (sw1, sw2) == (0x62, 0x82):
            print("INFO: Fin de archivo alcanzado (6282)")
            break
        elif (sw1, sw2) == (0x6A, 0x82):
            print("INFO: Archivo no encontrado o fin de datos")
            break
        else:
            print(f"ADVERTENCIA: Error en lectura: SW={sw1:02X} {sw2:02X}")
            break
            
    except Exception as e:
        print(f"ERROR: Error durante la transmision: {e}")
        break

print(f"INFO: Bytes leidos totales: {len(cert_data)}")

print("--- Primeros 128 bytes:")
hexdump(cert_data[:128])

# Paso 5: Buscar el certificado ASN.1 completo en TODOS los datos
print("... Buscando certificado ASN.1 en todos los datos leidos...")

if len(cert_data) == 0:
    print("ERROR: No se pudieron leer datos del certificado")
    sys.exit()

print(f"INFO: Total de datos leidos: {len(cert_data)} bytes")
print("--- Primeros 64 bytes:")
hexdump(cert_data[:64])

# Buscar el patrón del certificado X.509: 30 82 XX XX
start_asn1 = -1
for i in range(len(cert_data) - 10):
    if cert_data[i] == 0x30 and cert_data[i + 1] == 0x82:
        try:
            # Leer la longitud del certificado
            cert_length = (cert_data[i + 2] << 8) | cert_data[i + 3]
            total_cert_length = 4 + cert_length  # tag + longitud_bytes + contenido
            
            print(f"INFO: Patron 30 82 encontrado en offset {i}")
            print(f"INFO: Longitud del certificado: {cert_length} bytes")
            print(f"INFO: Longitud total requerida: {total_cert_length} bytes")
            print(f"INFO: Datos disponibles desde offset {i}: {len(cert_data) - i} bytes")
            
            # Verificar que tenemos suficientes datos
            if i + total_cert_length <= len(cert_data) and cert_length > 1000:
                start_asn1 = i
                print(f"OK: Certificado ASN.1 valido encontrado en offset {i}")
                
                # Verificar los primeros bytes del certificado para validar estructura
                cert_start = cert_data[i:i+16]
                print(f"--- Primeros 16 bytes del certificado en offset {i}:")
                hexdump(cert_start)
                
                # Buscar el patrón típico de un certificado: 30 82 XX XX 30 82 YY YY A0 03
                if (len(cert_data) > i + 10 and 
                    cert_data[i + 4] == 0x30 and cert_data[i + 5] == 0x82 and
                    cert_data[i + 8] == 0xA0 and cert_data[i + 9] == 0x03):
                    print(f"OK: Estructura de certificado X.509 valida confirmada")
                    break
                else:
                    print(f"ADVERTENCIA: Estructura de certificado invalida en offset {i}")
                    start_asn1 = -1
                    continue
            else:
                print(f"ADVERTENCIA: Datos insuficientes o certificado muy pequeno en offset {i}")
                
        except Exception as e:
            print(f"ADVERTENCIA: Error procesando offset {i}: {e}")
            continue

# También verificar si el certificado podría estar en el offset 0 del contenido del TLV
# El primer Tag 53 contiene solo 228 bytes, pero podría haber más TLVs
print(f"\n... Analizando estructura TLV completa...")
tlv_offset = 0
while tlv_offset < len(cert_data) - 3:
    if cert_data[tlv_offset] == 0x53:
        try:
            if cert_data[tlv_offset + 1] & 0x80:
                # Longitud larga
                length_bytes = cert_data[tlv_offset + 1] & 0x7F
                if length_bytes == 1:
                    tlv_length = cert_data[tlv_offset + 2]
                    content_start = tlv_offset + 3
                elif length_bytes == 2:
                    tlv_length = (cert_data[tlv_offset + 2] << 8) | cert_data[tlv_offset + 3]
                    content_start = tlv_offset + 4
                else:
                    tlv_offset += 1
                    continue
            else:
                tlv_length = cert_data[tlv_offset + 1]
                content_start = tlv_offset + 2
            
            print(f"INFO: TLV Tag 53 en offset {tlv_offset}: longitud {tlv_length} bytes")
            
            # Verificar si este TLV contiene un certificado válido
            if (content_start < len(cert_data) - 10 and
                cert_data[content_start] == 0x30 and cert_data[content_start + 1] == 0x82):
                print(f"INFO: Posible certificado ASN.1 en TLV offset {tlv_offset}")
                
            tlv_offset = content_start + tlv_length
        except Exception as e:
            tlv_offset += 1
    else:
        tlv_offset += 1

if start_asn1 == -1:
    print("ERROR: No se encontro un certificado ASN.1 valido con el metodo principal")
    print("... Intentando metodo alternativo...")
    
    # Método alternativo: buscar después de cada TLV Tag 53
    for tlv_start in range(len(cert_data) - 10):
        if cert_data[tlv_start] == 0x53:
            # Saltar el TLV header y buscar el certificado en el contenido
            try:
                if cert_data[tlv_start + 1] & 0x80:
                    length_bytes = cert_data[tlv_start + 1] & 0x7F
                    if length_bytes == 1:
                        content_start = tlv_start + 3
                    elif length_bytes == 2:
                        content_start = tlv_start + 4
                    else:
                        continue
                else:
                    content_start = tlv_start + 2
                
                # Buscar certificado justo después del TLV header
                if (content_start < len(cert_data) - 10 and
                    cert_data[content_start] == 0x30 and cert_data[content_start + 1] == 0x82):
                    
                    cert_length = (cert_data[content_start + 2] << 8) | cert_data[content_start + 3]
                    total_cert_length = 4 + cert_length
                    
                    if content_start + total_cert_length <= len(cert_data):
                        print(f"OK: Certificado encontrado usando metodo alternativo en offset {content_start}")
                        start_asn1 = content_start
                        break
                        
            except Exception:
                continue
    
    if start_asn1 == -1:
        print("ERROR: No se encontro un certificado ASN.1 valido")
        print("--- Mostrando primeros 512 bytes para analisis manual:")
        hexdump(cert_data[:512])
        sys.exit()

# Extraer el certificado encontrado
try:
    cert_length = (cert_data[start_asn1 + 2] << 8) | cert_data[start_asn1 + 3]
    total_length = 4 + cert_length
    
    clean_cert = cert_data[start_asn1:start_asn1 + total_length]
    print(f"INFO: Certificado extraido: {len(clean_cert)} bytes")
    print(f"... Verificando integridad del certificado:")
    print(f"   - Offset inicio:      {start_asn1}")
    print(f"   - Longitud esperada:  {total_length}")
    print(f"   - Longitud obtenida:  {len(clean_cert)}")
    
    # Verificar algunos patrones típicos de un certificado X.509 válido
    if len(clean_cert) >= 20:
        print(f"--- Primeros 20 bytes del certificado:")
        hexdump(clean_cert[:20])
        
        # Buscar patrones típicos
        valid_patterns = 0
        if clean_cert[0] == 0x30 and clean_cert[1] == 0x82:
            valid_patterns += 1
            print("OK: Header ASN.1 valido")
        if 0x30 in clean_cert[4:10] and 0x82 in clean_cert[4:10]:
            valid_patterns += 1  
            print("OK: TBSCertificate header encontrado")
        if b'PE' in clean_cert[:100]:  # País Perú
            valid_patterns += 1
            print("OK: Indicador de pais PE encontrado")
            
        print(f"INFO: Patrones validos encontrados: {valid_patterns}/3")
        
        if valid_patterns < 2:
            print("ADVERTENCIA: El certificado puede estar corrupto o mal extraido")
    
    if len(clean_cert) != total_length:
        print(f"ADVERTENCIA: Certificado incompleto. Esperado: {total_length}, Obtenido: {len(clean_cert)}")
        
        # Intentar usar todos los datos disponibles desde el offset encontrado
        max_available = len(cert_data) - start_asn1
        if max_available >= total_length:
            clean_cert = cert_data[start_asn1:start_asn1 + total_length]
            print(f"OK: Certificado reextraido usando todos los datos disponibles: {len(clean_cert)} bytes")
        else:
            print(f"ERROR: Datos insuficientes. Disponibles: {max_available}, Necesarios: {total_length}")
            sys.exit()
        
except Exception as e:
    print(f"ERROR: Error al extraer el certificado: {e}")
    sys.exit()

# Guardar certificado
with open("cert_auth_clean.cer", "wb") as f:
    f.write(clean_cert)
print("OK: Certificado guardado en cert_auth_clean.cer")



# Cerrar conexión
connection.disconnect()
print("\nOK: Conexion cerrada")