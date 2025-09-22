from smartcard.System import readers
from smartcard.Exceptions import NoCardException
from smartcard.util import toHexString

# ---------------------------
# AID de la aplicación PKI
# ---------------------------
AID_PKI = [
    0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xD2, 0x50,
    0x47, 0x65, 0x6E, 0x65, 0x72, 0x69, 0x63
]

# SELECT Application PKI
SELECT_PKI = [0x00, 0xA4, 0x04, 0x00, len(AID_PKI)] + AID_PKI

# ---------------------------
# File ID del certificado de autenticación
# (ejemplo típico en DNIe 2.0: '0x0002', puede variar en 3.0)
# ---------------------------
SELECT_AUTH_CERT = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x02]

def read_binary(connection):
    """Lee completo el EF seleccionado concatenando READ BINARY"""
    data = []
    offset = 0
    chunk_size = 0xFF  # máximo por APDU

    while True:
        p1 = (offset >> 8) & 0xFF
        p2 = offset & 0xFF
        apdu = [0x00, 0xB0, p1, p2, chunk_size]
        response, sw1, sw2 = connection.transmit(apdu)

        if (sw1, sw2) == (0x90, 0x00):
            data.extend(response)
            if len(response) < chunk_size:
                break  # fin de archivo
            offset += len(response)
        else:
            print(f"Error en READ BINARY: SW1={sw1:02X}, SW2={sw2:02X}")
            break

    return bytes(data)

def main():
    try:
        # Conexión al lector
        r = readers()
        if not r:
            print("No hay lectores conectados.")
            return

        connection = r[0].createConnection()
        connection.connect()

        # 1. SELECT AID PKI
        response, sw1, sw2 = connection.transmit(SELECT_PKI)
        if (sw1, sw2) != (0x90, 0x00):
            print(f"Error SELECT PKI: SW1={sw1:02X}, SW2={sw2:02X}")
            return
        print("✔ Aplicación PKI seleccionada")

        # 2. SELECT EF certificado autenticación
        response, sw1, sw2 = connection.transmit(SELECT_AUTH_CERT)
        if (sw1, sw2) != (0x90, 0x00):
            print(f"Error SELECT EF: SW1={sw1:02X}, SW2={sw2:02X}")
            return
        print("✔ EF del certificado seleccionado")

    except NoCardException:
        print("No hay tarjeta insertada en el lector")

if __name__ == "__main__":
    main()