import base64
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA1  # <--- 1. IMPORT a different SHA1 module

def decrypt_string(encrypted_string: str) -> str:
    """
    Decrypts a string using logic equivalent to the VB.NET function.
    Assumes AES-256 CBC with PKCS7 padding and a key derived using PBKDF2-HMAC-SHA1.
    """
    if not encrypted_string:
        return ""

    # --- Parameters from the VB.NET function ---
    password = "N3st22"
    salt_str = "88552299"
    password_iterations = 2
    initial_vector_str = "464R5DFA5DL6LE28"
    key_size_bits = 256
    
    try:
        # 1. Decode the input from Base64
        encrypted_bytes = base64.b64decode(encrypted_string)

        # 2. Prepare the cryptographic inputs by encoding them to bytes
        salt_bytes = salt_str.encode('ascii')
        iv_bytes = initial_vector_str.encode('ascii')

        # 3. Derive the key from the password and salt using PBKDF2
        key_bytes = PBKDF2(
            password,
            salt_bytes,
            dkLen=key_size_bits // 8,
            count=password_iterations,
            hmac_hash_module=SHA1  # <--- 2. USE the imported SHA1 module
        )
        
        # 4. Create the AES cipher object in CBC mode
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        
        # 5. Decrypt the data and unpad the result
        decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
        decrypted_unpadded_bytes = unpad(decrypted_padded_bytes, AES.block_size)
        
        # 6. Decode the final bytes into a string
        return decrypted_unpadded_bytes.decode('utf-8')

    except (ValueError, KeyError) as e:
        return f"Decryption failed. The input may be invalid or the key incorrect. Error: {e}"

# --- Main part of the script to run ---
if __name__ == "__main__":
    encrypted_input = input("Enter the encrypted string to decode: ")
    decrypted_output = decrypt_string(encrypted_input)
    
    print("\n--- Decrypted Result ---")
    print(decrypted_output)
