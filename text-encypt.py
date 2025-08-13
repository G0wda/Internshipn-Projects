from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64


# ---------- AES Encryption ----------
def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()


def aes_decrypt(ciphertext_b64, key):
    data = base64.b64decode(ciphertext_b64)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


# ---------- DES Encryption ----------
def des_encrypt(text, key):
    cipher = DES.new(key, DES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()


def des_decrypt(ciphertext_b64, key):
    data = base64.b64decode(ciphertext_b64)
    nonce, tag, ciphertext = data[:8], data[8:16], data[16:]
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


# ---------- RSA Encryption ----------
def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def rsa_encrypt(text, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(text.encode())).decode()


def rsa_decrypt(ciphertext_b64, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(ciphertext_b64)).decode()


# ---------- Main Program ----------
if __name__ == "__main__":
    message = input("Enter the message to encrypt: ")

    print("\nChoose encryption algorithm:")
    print("1. AES")
    print("2. DES")
    print("3. RSA")
    choice = input("Enter your choice (1/2/3): ")

    if choice == "1":
        aes_key = get_random_bytes(16)  # 128-bit key
        encrypted = aes_encrypt(message, aes_key)
        decrypted = aes_decrypt(encrypted, aes_key)

        print("\n[ AES Encryption ]")
        print("Key (base64):", base64.b64encode(aes_key).decode())
        print("Encrypted:", encrypted)
        print("Decrypted:", decrypted)

    elif choice == "2":
        des_key = get_random_bytes(8)  # 64-bit key
        encrypted = des_encrypt(message, des_key)
        decrypted = des_decrypt(encrypted, des_key)

        print("\n[ DES Encryption ]")
        print("Key (base64):", base64.b64encode(des_key).decode())
        print("Encrypted:", encrypted)
        print("Decrypted:", decrypted)

    elif choice == "3":
        private_key, public_key = rsa_generate_keys()
        encrypted = rsa_encrypt(message, public_key)
        decrypted = rsa_decrypt(encrypted, private_key)

        print("\n[ RSA Encryption ]")
        print("Public Key:\n", public_key.decode())
        print("Private Key:\n", private_key.decode())
        print("Encrypted:", encrypted)
        print("Decrypted:", decrypted)

    else:
        print("Invalid choice! Please select 1, 2, or 3.")
