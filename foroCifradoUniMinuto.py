#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
====================================================================
  APLICATIVO DE CIFRADO SIMETRICO (CLAVE PRIVADA) - AES-256
  Caso: Banco / Entidad Financiera
  Curso: Seguridad en el Desarrollo de Software
  Estudiante : Alland Key Naranjo Plaza
====================================================================

Este programa demuestra el CIFRADO SIMETRICO usando AES-256, el
estandar actual (NIST, 2001) descrito por Hernandez (2016) y
Maillo (2017).

Idea central (cifrado de clave privada):
  - Se usa UNA SOLA clave secreta para cifrar Y descifrar.
  - Esa clave debe mantenerse en secreto (principio de Kerckhoffs:
    la seguridad depende de la clave, no del algoritmo).

Ejemplo de uso en un banco: proteger datos sensibles de clientes
(numero de cuenta, saldo, cedula) antes de almacenarlos o
transmitirlos, de modo que solo se puedan leer con la clave correcta.
"""

import os
import base64
import getpass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding

# --- Parametros del criptosistema ---
LONGITUD_CLAVE = 32      # 32 bytes = 256 bits  -> AES-256
ITERACIONES_KDF = 200_000  # refuerza la contrasena contra fuerza bruta


def derivar_clave(contrasena: str, salt: bytes) -> bytes:
    """
    Convierte la contrasena del usuario en una clave AES de 256 bits.
    Se usa PBKDF2 con un 'salt' aleatorio para que la misma contrasena
    no genere siempre la misma clave.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=LONGITUD_CLAVE,
        salt=salt,
        iterations=ITERACIONES_KDF,
    )
    return kdf.derive(contrasena.encode("utf-8"))


def cifrar(texto_claro: str, contrasena: str) -> str:
    """
    Cifra un texto con AES-256 en modo CBC.
    Devuelve un texto Base64 que contiene: salt + IV + criptograma.
    (Base64 se usa porque el cifrado produce bytes no imprimibles,
     tal como explica Hernandez, 2016.)
    """
    salt = os.urandom(16)          # sal aleatoria para derivar la clave
    iv = os.urandom(16)            # vector de inicializacion (16 bytes)
    clave = derivar_clave(contrasena, salt)

    # AES trabaja por bloques de 128 bits -> hay que rellenar (padding)
    relleno = padding.PKCS7(algorithms.AES.block_size).padder()
    datos = relleno.update(texto_claro.encode("utf-8")) + relleno.finalize()

    cifrador = Cipher(algorithms.AES(clave), modes.CBC(iv)).encryptor()
    criptograma = cifrador.update(datos) + cifrador.finalize()

    # Empaquetamos todo junto y lo pasamos a Base64 (legible)
    paquete = salt + iv + criptograma
    return base64.b64encode(paquete).decode("utf-8")


def descifrar(texto_base64: str, contrasena: str) -> str:
    """
    Descifra un texto producido por cifrar().
    Si la contrasena es incorrecta o el dato esta corrupto, lanza error.
    """
    paquete = base64.b64decode(texto_base64)
    salt = paquete[:16]
    iv = paquete[16:32]
    criptograma = paquete[32:]

    clave = derivar_clave(contrasena, salt)

    descifrador = Cipher(algorithms.AES(clave), modes.CBC(iv)).decryptor()
    datos_con_relleno = descifrador.update(criptograma) + descifrador.finalize()

    quitar_relleno = padding.PKCS7(algorithms.AES.block_size).unpadder()
    texto = quitar_relleno.update(datos_con_relleno) + quitar_relleno.finalize()
    return texto.decode("utf-8")


def menu():
    print("=" * 60)
    print("  CIFRADO SIMETRICO AES-256  |  Caso: Banco / Financiera")
    print("=" * 60)
    while True:
        print("\nSeleccione una opcion:")
        print("  1. Cifrar informacion (proteger dato del cliente)")
        print("  2. Descifrar informacion (recuperar dato)")
        print("  3. Salir")
        opcion = input("Opcion: ").strip()

        if opcion == "1":
            texto = input("\nEscriba el dato a proteger (ej. saldo, cuenta): ")
            clave = getpass.getpass("Clave secreta del banco: ")
            resultado = cifrar(texto, clave)
            print("\n--- DATO CIFRADO (guardar/transmitir esto) ---")
            print(resultado)

        elif opcion == "2":
            texto = input("\nPegue el dato cifrado (Base64): ").strip()
            clave = getpass.getpass("Clave secreta del banco: ")
            try:
                resultado = descifrar(texto, clave)
                print("\n--- DATO ORIGINAL RECUPERADO ---")
                print(resultado)
            except Exception:
                print("\n[ERROR] Clave incorrecta o dato alterado.")
                print("        No se pudo recuperar la informacion.")
                print("        (Demuestra el principio de Kerckhoffs: sin la")
                print("         clave correcta, el dato es inutil.)")

        elif opcion == "3":
            print("\nSaliendo. Recuerde: la seguridad depende del secreto de la clave.")
            break
        else:
            print("Opcion no valida.")


if __name__ == "__main__":
    menu()