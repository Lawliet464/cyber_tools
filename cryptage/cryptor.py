# cryptor.py
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from io import BytesIO
import base64
import zlib
import os

KEY_PUBLIC = "key.pub"
KEY_PRIVATE = "key.pri"


def generate(key_size: int = 2048):
    """
    Génère une paire de clés RSA (privée + publique) et les écrit sur disque.
    """
    new_key = RSA.generate(key_size)
    private_key = new_key.export_key()
    public_key = new_key.publickey().export_key()

    with open(KEY_PRIVATE, "wb") as f:
        f.write(private_key)

    with open(KEY_PUBLIC, "wb") as f:
        f.write(public_key)

    print(f"Clés générées : {KEY_PRIVATE}, {KEY_PUBLIC}")


def get_rsa_cipher(keytype: str):
    """
    Renvoie (cipher_obj, key_size_in_bytes) pour le type 'pub' ou 'pri'.
    keytype doit être 'pub' ou 'pri' (correspondant à key.pub / key.pri).
    """
    filename = f"key.{keytype}"
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Le fichier de clé '{filename}' n'existe pas. Génère d'abord les clés avec generate().")

    # lire en binaire (les clés ont été écrites en binaire)
    with open(filename, "rb") as f:
        key_data = f.read()

    rsakey = RSA.import_key(key_data)
    cipher = PKCS1_OAEP.new(rsakey)
    return cipher, rsakey.size_in_bytes()


def encrypt(plaintext: bytes) -> bytes:
    """
    Chiffre les données (bytes) et renvoie une payload encodée en base64 (bytes).
    Schéma : encrypted_session_key || nonce || tag || ciphertext
    """
    # compresser le texte (optionnel mais utile)
    compressed_text = zlib.compress(plaintext)

    # session key AES (128 bits ici)
    session_key = get_random_bytes(16)

    # chiffrement symétrique (AES EAX -> fournit nonce + tag + ciphertext)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_text)

    # chiffre la session key avec la clé RSA publique
    cipher_rsa, _ = get_rsa_cipher("pub")
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    # concatener tout dans une charge utile et encoder en base64
    msg_payload = encrypted_session_key + cipher_aes.nonce + tag + ciphertext
    encrypted = base64.encodebytes(msg_payload)
    return encrypted


def decrypt(encrypted: bytes) -> bytes:
    """
    Déchiffre une payload encodée en base64 (bytes) et renvoie le plaintext (bytes).
    Attend le format produit par encrypt().
    """
    encrypted_bytes = BytesIO(base64.decodebytes(encrypted))

    # récupérer cipher RSA (privée) et taille de la clé pour lire la session key chiffrée
    cipher_rsa, keysize_in_bytes = get_rsa_cipher("pri")

    # lire chaque portion dans le même ordre que lors de l'encodage
    encrypted_session_key = encrypted_bytes.read(keysize_in_bytes)
    nonce = encrypted_bytes.read(16)  # nonce EAX = 16 octets
    tag = encrypted_bytes.read(16)    # tag EAX = 16 octets
    ciphertext = encrypted_bytes.read()

    # déchiffrer la session key avec la clé RSA privée
    session_key = cipher_rsa.decrypt(encrypted_session_key)

    # déchiffrer le message avec AES EAX
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # décompresser et renvoyer
    plaintext = zlib.decompress(decrypted)
    return plaintext


if __name__ == "__main__":
    # Exemple d'utilisation
    # 1) Générer les clés (décommenter si tu veux forcer génération à chaque exécution)
    if not (os.path.exists(KEY_PRIVATE) and os.path.exists(KEY_PUBLIC)):
        generate()

    # 2) Test encrypt / decrypt
    plaintext = b"hey there you."
    encrypted = encrypt(plaintext)
    print("Encrypted (base64):")
    print(encrypted.decode())  # affichage lisible (base64)

    decrypted = decrypt(encrypted)
    print("Decrypted:")
    print(decrypted.decode())
