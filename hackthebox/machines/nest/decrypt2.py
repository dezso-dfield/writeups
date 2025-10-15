import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad

def decrypt_string(encrypted_string: str) -> str:
    """
    Replicates the C# decryption logic using AES-256 and PBKDF2.
    """
    if not encrypted_string:
        return ""

    # --- Parameters from the C# code ---
    password = "667912"
    salt_str = "1313Rf99"
    iv_str = "1L1SA61493DRV53Z"
    password_iterations = 3
    key_size_bits = 256

    try:
        # 1. Decode the input from Base64
        encrypted_bytes = base64.b64decode(encrypted_string)

        # 2. Prepare cryptographic inputs by encoding them to ASCII bytes
        salt_bytes = salt_str.encode('ascii')
        iv_bytes = iv_str.encode('ascii')

        # 3. Derive the decryption key using PBKDF2
        #    .NET's Rfc2898DeriveBytes defaults to HMAC-SHA1.
        #    Key size is 256 bits, which is 32 bytes.
        key_bytes = PBKDF2(
            password,
            salt_bytes,
            dkLen=key_size_bits // 8,
            count=password_iterations,
            hmac_hash_module=SHA1
        )
        
        # 4. Create the AES cipher in CBC mode
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        
        # 5. Decrypt the data and remove the PKCS7 padding
        decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
        decrypted_unpadded_bytes = unpad(decrypted_padded_bytes, AES.block_size)
        
        # 6. Decode the final bytes back into a string using ASCII
        return decrypted_unpadded_bytes.decode('ascii')

    except (ValueError, KeyError) as e:
        return f"Decryption failed. Error: {e}"

# --- Main part of the script to run ---
if __name__ == "__main__":
    # Prompt the user for the encrypted string
    encrypted_input = input("Enter the encrypted string to decode: ")
    
    # Decrypt the string and print the result
    decrypted_output = decrypt_string(encrypted_input)
    
    print("\n--- Decrypted Result ---")
    print(decrypted_output)

