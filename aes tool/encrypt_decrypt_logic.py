import os # 1. Import Necessary Python Libraries (Our 'LEGO Blocks')
import os # For generating random bytes (for Key and IV)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # For AES algorithm
from cryptography.hazmat.backends import default_backend # For cryptographic backend support
from cryptography.hazmat.primitives import padding # For padding data (essential for AES)

# --- GLOBAL KEY AND IV (For testing purposes only. In a real app, these would be managed differently) ---
# For demonstration, we'll generate them once. In a real app, the user might input a password
# from which a key is derived, and IV would be unique per encryption.
# These will be used by our test calls at the end of the script.

# Generate a random 32-byte key (256 bits for AES-256)
GLOBAL_KEY = os.urandom(32)

# Generate a random 16-byte IV (Initialization Vector)
# Important: For each *new* encryption, a unique IV should be used.
# For decryption, the *same* IV that was used during encryption is needed.
# We'll prepend this IV to the encrypted file.
GLOBAL_IV = os.urandom(16)

print(f"Generated GLOBAL_KEY (hex): {GLOBAL_KEY.hex()}")
print(f"Generated GLOBAL_IV (hex): {GLOBAL_IV.hex()}")

# --- ENCRYPTION FUNCTION ---
def encrypt_file(input_filepath, output_filepath, encryption_key):
    """
    Encrypts the content of an input file using AES-256 (CBC mode)
    and writes the encrypted content (prefixed with a newly generated IV)
    to an output file.

    Args:
        input_filepath (str): Path to the file to be encrypted.
        output_filepath (str): Path where the encrypted file will be saved.
        encryption_key (bytes): The 32-byte (256-bit) AES encryption key.

    Returns:
        bool: True if encryption was successful, False otherwise.
    """
    try:
        # Generate a NEW IV for this specific encryption operation
        # This is crucial for security. Each encryption should have a unique IV.
        current_iv = os.urandom(16)

        # 1. Read the Input File Content (in binary mode)
        with open(input_filepath, 'rb') as f_in:
            plaintext = f_in.read()

        # 2. Apply Padding to the Data
        # AES operates on fixed-size blocks (16 bytes). If the data isn't a multiple of 16,
        # we add padding using PKCS7 standard.
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # 3. Create the AES Cipher Object
        # This sets up the AES algorithm with our key, IV, and mode (CBC).
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(current_iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # 4. Encrypt the Padded Data
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # 5. Write Encrypted Data to the Output File
        # Crucially, we write the IV first, then the ciphertext.
        # The IV is needed for decryption and does not need to be secret.
        with open(output_filepath, 'wb') as f_out:
            f_out.write(current_iv) # Write the IV first
            f_out.write(ciphertext) # Then write the actual encrypted data

        print(f"File '{input_filepath}' successfully encrypted to '{output_filepath}'")
        return True
    except FileNotFoundError:
        print(f"Error: Input file '{input_filepath}' not found.")
        return False
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return False

# --- DECRYPTION FUNCTION ---
def decrypt_file(input_filepath, output_filepath, encryption_key):
    """
    Decrypts the content of an encrypted file (which should be prefixed with its IV)
    using AES-256 (CBC mode) and writes the original content to an output file.

    Args:
        input_filepath (str): Path to the encrypted file.
        output_filepath (str): Path where the decrypted file will be saved.
        encryption_key (bytes): The 32-byte (256-bit) AES encryption key used during encryption.

    Returns:
        bool: True if decryption was successful, False otherwise.
    """
    try:
        # 1. Read the Encrypted File Content (in binary mode)
        with open(input_filepath, 'rb') as f_in:
            # First 16 bytes are the IV
            retrieved_iv = f_in.read(16)
            # The rest is the actual ciphertext
            ciphertext = f_in.read()

        # Check if we got enough data (at least an IV)
        if len(retrieved_iv) < 16:
            print(f"Error: '{input_filepath}' is not a valid encrypted file (IV missing or incomplete).")
            return False

        # 2. Create the AES Cipher Object for Decryption
        # Use the SAME key and the RETRIEVED IV for decryption.
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(retrieved_iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # 3. Decrypt the Ciphertext
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # 4. Remove Padding from the Decrypted Data
        # This reverses the padding step done during encryption.
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        # 5. Write Decrypted Data to the Output File
        with open(output_filepath, 'wb') as f_out:
            f_out.write(plaintext)

        print(f"File '{input_filepath}' successfully decrypted to '{output_filepath}'")
        return True
    except FileNotFoundError:
        print(f"Error: Encrypted file '{input_filepath}' not found.")
        return False
    except Exception as e:
        print(f"An error occurred during decryption. Check if the key is correct or file is corrupted: {e}")
        return False

# --- TESTING THE CORE LOGIC (Run this from your terminal) ---
if __name__ == "__main__":
    # Create a sample text file for testing
    sample_filename = "my_secret_document.txt"
    encrypted_filename = "my_secret_document.encrypted"
    decrypted_filename = "my_secret_document_decrypted.txt"

    with open(sample_filename, "w") as f:
        f.write("This is a very important secret message.\n")
        f.write("Please keep it confidential!")
    print(f"\n--- Created sample file: {sample_filename} ---")

    # --- Test Encryption ---
    print("\n--- Testing Encryption ---")
    if encrypt_file(sample_filename, encrypted_filename, GLOBAL_KEY):
        print(f"Encryption successful. Check '{encrypted_filename}' for 'gubulu gubulu' content.")
        # Try opening encrypted_filename in Notepad/VS Code to see its unreadable content.
    else:
        print("Encryption failed.")

    # --- Test Decryption ---
    print("\n--- Testing Decryption ---")
    if decrypt_file(encrypted_filename, decrypted_filename, GLOBAL_KEY):
        print(f"Decryption successful. Check '{decrypted_filename}' to confirm original content.")
        # Open decrypted_filename to ensure it matches sample_filename.
    else:
        print("Decryption failed.")

    # --- Test Decryption with WRONG KEY (Expected to fail or produce garbage) ---
    print("\n--- Testing Decryption with WRONG KEY (Expected behavior: Error or garbage) ---")
    wrong_key = os.urandom(32) # A different, wrong key
    decrypt_file(encrypted_filename, "decrypted_with_wrong_key.txt", wrong_key)
    print("If decryption with wrong key produced garbage or an error, it worked as expected!")