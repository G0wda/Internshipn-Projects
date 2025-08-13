from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

# Function to pad data to be multiple of 16 bytes
def pad(data):
    return data + b"\0" * (16 - len(data) % 16)

# AES Encryption
def encrypt_image(image_path, key):
    with open(image_path, "rb") as f:
        image_data = f.read()
    
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(pad(image_data))
    
    encrypted_data = cipher.nonce + tag + ciphertext
    enc_file = image_path + ".enc"
    
    with open(enc_file, "wb") as f:
        f.write(encrypted_data)
    
    print(f"[+] Image encrypted successfully: {enc_file}")

# AES Decryption
def decrypt_image(enc_image_path, key, output_path):
    with open(enc_image_path, "rb") as f:
        data = f.read()
    
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    
    with open(output_path, "wb") as f:
        f.write(decrypted_data.rstrip(b"\0"))
    
    print(f"[+] Image decrypted successfully: {output_path}")

# Main Program
if __name__ == "__main__":
    print("Image Encryption Tool")
    print("1. Encrypt Image")
    print("2. Decrypt Image")
    choice = input("Enter choice (1/2): ")

    key = get_random_bytes(16)  # AES 128-bit key
    print(f"[!] Save this key securely (Base64): {base64.b64encode(key).decode()}")

    if choice == "1":
        img_path = input("Enter image path to encrypt: ")
        if os.path.exists(img_path):
            encrypt_image(img_path, key)
        else:
            print("[-] File not found!")

    elif choice == "2":
        enc_path = input("Enter encrypted file path: ")
        b64_key = input("Enter Base64 key: ")
        key = base64.b64decode(b64_key)
        output_path = input("Enter output decrypted image filename: ")
        
        if os.path.exists(enc_path):
            decrypt_image(enc_path, key, output_path)
        else:
            print("[-] File not found!")

    else:
        print("Invalid choice!")
