import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox, scrolledtext
import cv2
import os
import numpy as np
import logging

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag 

DELIMITER = "_||_"
DELIMITER_BIN = ''.join(format(ord(char), '08b') for char in DELIMITER)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SALT_SIZE = 16  
NONCE_SIZE = 12 
KEY_SIZE = 32   
PBKDF2_ITERATIONS = 390000

# --- Steganography & Crypto Core Functions ---

def bytes_to_binary(data_bytes):
    return ''.join(format(byte, '08b') for byte in data_bytes)

def binary_to_bytes(binary_string):
    if len(binary_string) % 8 != 0:
        logging.warning(f"Binary string length {len(binary_string)} not multiple of 8. Padding may be incorrect.")
        raise ValueError("Binary string length is not a multiple of 8")

    try:
        return bytes(int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8))
    except ValueError as e:
        logging.error(f"Error converting binary to bytes: {e}. Binary chunk: {binary_string[:64]}...")
        raise ValueError(f"Invalid binary sequence encountered: {e}") from e

def encrypt_data(password: str, plaintext: str) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty for encryption.")
    try:
        plaintext_bytes = plaintext.encode('utf-8')
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(password.encode('utf-8'))

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None) 

        logging.info(f"Encryption successful. Salt: {len(salt)}B, Nonce: {len(nonce)}B, Ciphertext+Tag: {len(ciphertext)}B")
        return salt + nonce + ciphertext
    except Exception as e:
        logging.exception("Encryption failed:")
        raise RuntimeError(f"Encryption failed: {e}") from e

def decrypt_data(password: str, encrypted_data_payload: bytes) -> str:
    if not password:
        raise ValueError("Password cannot be empty for decryption.")
    if len(encrypted_data_payload) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Encrypted data is too short (missing salt/nonce).")

    try:
        salt = encrypted_data_payload[:SALT_SIZE]
        nonce = encrypted_data_payload[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        ciphertext = encrypted_data_payload[SALT_SIZE + NONCE_SIZE :]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(password.encode('utf-8'))

        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)

        logging.info("Decryption and tag verification successful.")
        return decrypted_bytes.decode('utf-8')

    except InvalidTag:
        logging.error("Decryption failed: Invalid password, corrupted data, or incorrect salt/nonce.")
        raise ValueError("Decryption failed: Invalid key or corrupted data.") 
    except Exception as e:
        logging.exception("Decryption failed:")
        raise RuntimeError(f"Decryption failed: {e}") from e

def encode_lsb(image_path, secret_message, password, output_path):
    try:
        encrypted_payload = encrypt_data(password, secret_message)

        binary_payload = bytes_to_binary(encrypted_payload) + DELIMITER_BIN
        payload_len_bits = len(binary_payload)

        image = cv2.imread(image_path)
        if image is None:
            raise FileNotFoundError(f"Could not read image file: {image_path}")

        height, width, channels = image.shape
        max_bits = height * width * channels
        logging.info(f"Image dimensions: {width}x{height}x{channels}. Max embeddable bits: {max_bits}")
        logging.info(f"Encrypted payload + delimiter size: {payload_len_bits} bits.")

        if payload_len_bits > max_bits:
            raise ValueError(f"Encrypted message ({payload_len_bits} bits) is too large for the image (max {max_bits} bits).")

        data_index = 0
        for y in range(height):
            for x in range(width):
                for c in range(channels):
                    if data_index < payload_len_bits:
                        pixel_val = image[y, x, c]
                        image[y, x, c] = (pixel_val & 0xFE) | int(binary_payload[data_index])
                        data_index += 1
                    else: break
                if data_index >= payload_len_bits: break
            if data_index >= payload_len_bits: break

        logging.info(f"Finished embedding {data_index} bits.")

        success = cv2.imwrite(output_path, image)
        if not success:
             raise IOError(f"Failed to save the stego image to {output_path}")

        return True, f"Message encrypted and hidden successfully in {os.path.basename(output_path)}"

    except (FileNotFoundError, ValueError, IOError, RuntimeError) as e:
        logging.error(f"Encoding process failed: {e}")
        return False, str(e)
    except Exception as e:
        logging.exception("An unexpected error occurred during encoding:")
        return False, f"An unexpected error occurred: {e}"


def decode_lsb(stego_image_path, password):
    try:
        image = cv2.imread(stego_image_path)
        if image is None:
            raise FileNotFoundError(f"Could not read stego image file: {stego_image_path}")

        height, width, channels = image.shape
        logging.info(f"Decoding image: {width}x{height}x{channels}")

        extracted_binary = ""
        delimiter_len = len(DELIMITER_BIN)
        found = False
        for y in range(height):
            for x in range(width):
                for c in range(channels):
                    pixel_val = image[y, x, c]
                    extracted_binary += str(pixel_val & 1)
                    if len(extracted_binary) >= delimiter_len and extracted_binary.endswith(DELIMITER_BIN):
                        found = True
                        logging.info(f"Delimiter found after extracting {len(extracted_binary)} bits.")
                        break
                if found: break
            if found: break

        if not found:
            return False, "Could not find the end-of-message delimiter. No hidden message found or image is corrupted."

        encrypted_binary = extracted_binary[:-delimiter_len]
        encrypted_payload_bytes = binary_to_bytes(encrypted_binary) 

        decrypted_message = decrypt_data(password, encrypted_payload_bytes) 

        return True, decrypted_message

    except (FileNotFoundError, ValueError, RuntimeError) as e:
         logging.error(f"Decoding process failed: {e}")
         return False, str(e)
    except Exception as e:
        logging.exception("An unexpected error occurred during decoding:")
        return False, f"An unexpected error occurred during decoding: {e}"

class StegoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Steganography Tool") 
        self.geometry("650x600") 
        self.resizable(True, True)

        self.style = ttk.Style(self)
        self.style.theme_use('clam')

        self.cover_image_path = tk.StringVar()
        self.output_image_path = tk.StringVar()
        self.stego_image_path_decode = tk.StringVar()
        self.encode_password = tk.StringVar() 
        self.decode_password = tk.StringVar() 

        tabControl = ttk.Notebook(self)
        self.tab_encode = ttk.Frame(tabControl)
        self.tab_decode = ttk.Frame(tabControl)

        tabControl.add(self.tab_encode, text='Hide Encrypted Message')
        tabControl.add(self.tab_decode, text='Extract Encrypted Message') 
        tabControl.pack(expand=1, fill="both", padx=10, pady=5)

        self.setup_encode_tab()
        self.setup_decode_tab()

    def setup_encode_tab(self):
        frame = self.tab_encode
        row_idx = 0 

        ttk.Label(frame, text="1. Select Cover Image (e.g., PNG, BMP):", font=('Arial', 10, 'bold')).grid(row=row_idx, column=0, padx=5, pady=5, sticky='w'); row_idx += 1
        ttk.Entry(frame, textvariable=self.cover_image_path, width=50).grid(row=row_idx, column=0, padx=5, pady=2, sticky='ew')
        ttk.Button(frame, text="Browse...", command=lambda: self.select_file(self.cover_image_path, "Select Cover Image", [("Image Files", "*.png *.bmp *.tiff"), ("All Files", "*.*")])).grid(row=row_idx, column=1, padx=5, pady=2); row_idx += 1

        ttk.Label(frame, text="2. Enter Secret Message:", font=('Arial', 10, 'bold')).grid(row=row_idx, column=0, padx=5, pady=5, sticky='w'); row_idx += 1
        self.secret_text_widget = scrolledtext.ScrolledText(frame, height=8, width=60, wrap=tk.WORD)
        self.secret_text_widget.grid(row=row_idx, column=0, columnspan=2, padx=5, pady=2, sticky='ew'); row_idx += 1

        ttk.Label(frame, text="3. Enter Password/Key:", font=('Arial', 10, 'bold')).grid(row=row_idx, column=0, padx=5, pady=5, sticky='w'); row_idx += 1
        self.encode_password_entry = ttk.Entry(frame, textvariable=self.encode_password, width=50, show='*')
        self.encode_password_entry.grid(row=row_idx, column=0, padx=5, pady=2, sticky='ew')
        row_idx += 1

        ttk.Label(frame, text="4. Select Output Image Path:", font=('Arial', 10, 'bold')).grid(row=row_idx, column=0, padx=5, pady=5, sticky='w'); row_idx += 1
        ttk.Entry(frame, textvariable=self.output_image_path, width=50).grid(row=row_idx, column=0, padx=5, pady=2, sticky='ew')
        ttk.Button(frame, text="Save As...", command=lambda: self.save_file(self.output_image_path, "Save Stego Image As", [("PNG Image", "*.png"), ("BMP Image", "*.bmp"), ("TIFF Image", "*.tiff")])).grid(row=row_idx, column=1, padx=5, pady=2); row_idx += 1

        self.encode_button = ttk.Button(frame, text="Encrypt & Hide", command=self.run_encode, width=20) 
        self.encode_button.grid(row=row_idx, column=0, columnspan=2, padx=5, pady=20); row_idx += 1

        frame.columnconfigure(0, weight=1)


    def setup_decode_tab(self):
        frame = self.tab_decode
        row_idx = 0

        ttk.Label(frame, text="1. Select Stego Image:", font=('Arial', 10, 'bold')).grid(row=row_idx, column=0, padx=5, pady=5, sticky='w'); row_idx += 1
        ttk.Entry(frame, textvariable=self.stego_image_path_decode, width=50).grid(row=row_idx, column=0, padx=5, pady=2, sticky='ew')
        ttk.Button(frame, text="Browse...", command=lambda: self.select_file(self.stego_image_path_decode, "Select Stego Image", [("Image Files", "*.png *.bmp *.tiff"), ("All Files", "*.*")])).grid(row=row_idx, column=1, padx=5, pady=2); row_idx += 1

        ttk.Label(frame, text="2. Enter Password/Key:", font=('Arial', 10, 'bold')).grid(row=row_idx, column=0, padx=5, pady=5, sticky='w'); row_idx += 1
        self.decode_password_entry = ttk.Entry(frame, textvariable=self.decode_password, width=50, show='*') 
        self.decode_password_entry.grid(row=row_idx, column=0, padx=5, pady=2, sticky='ew')
        row_idx += 1

        self.decode_button = ttk.Button(frame, text="Extract & Decrypt", command=self.run_decode, width=20) 
        self.decode_button.grid(row=row_idx, column=0, columnspan=2, padx=5, pady=20); row_idx += 1

        ttk.Label(frame, text="Extracted Message:", font=('Arial', 10, 'bold')).grid(row=row_idx, column=0, padx=5, pady=5, sticky='w'); row_idx += 1
        self.extracted_text_widget = scrolledtext.ScrolledText(frame, height=12, width=60, wrap=tk.WORD, state='disabled')
        self.extracted_text_widget.grid(row=row_idx, column=0, columnspan=2, padx=5, pady=2, sticky='nsew'); row_idx += 1

        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(row_idx -1, weight=1) 

    def select_file(self, path_var, title, filetypes):
        """Opens a file dialog to select a file and updates the path_var."""
        filepath = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if filepath:
            path_var.set(filepath)
            logging.info(f"File selected: {filepath}")

    def save_file(self, path_var, title, filetypes):
        """Opens a file dialog to save a file and updates the path_var."""
        default_ext = filetypes[0][1].split('.')[-1] if filetypes else ".png"
        filepath = filedialog.asksaveasfilename(title=title, filetypes=filetypes, defaultextension=default_ext)
        if filepath:
            path_var.set(filepath)
            logging.info(f"Output file path set: {filepath}")


    def run_encode(self):
        cover_path = self.cover_image_path.get()
        secret = self.secret_text_widget.get("1.0", tk.END).strip()
        output_path = self.output_image_path.get()
        password = self.encode_password.get() 

        if not os.path.exists(cover_path): messagebox.showerror("Error", "Cover image file does not exist."); return
        if not secret: messagebox.showerror("Error", "Secret message cannot be empty."); return
        if not output_path: messagebox.showerror("Error", "Please specify an output file path."); return
        if not password: messagebox.showerror("Error", "Password cannot be empty for encryption."); return 
        if os.path.dirname(output_path) and not os.path.exists(os.path.dirname(output_path)): messagebox.showerror("Error", f"Output directory does not exist: {os.path.dirname(output_path)}"); return
        if cover_path == output_path: messagebox.showerror("Error", "Cover image and output image cannot be the same file."); return

        self.encode_button.config(state='disabled')
        self.update_idletasks() 

        logging.info("Starting encoding process...")
        success, message = encode_lsb(cover_path, secret, password, output_path)

        self.encode_button.config(state='normal')

        if success:
            messagebox.showinfo("Success", message)
            logging.info(f"Encoding successful: {message}")
        else:
            messagebox.showerror("Encoding Failed", message)
            logging.error(f"Encoding failed: {message}")


    def run_decode(self):
        stego_path = self.stego_image_path_decode.get()
        password = self.decode_password.get() 

        if not os.path.exists(stego_path): messagebox.showerror("Error", "Stego image file does not exist."); return
        if not password: messagebox.showerror("Error", "Password cannot be empty for decryption."); return 

        self.decode_button.config(state='disabled')
        self.update_idletasks() 

        logging.info("Starting decoding process...")
        success, message_or_data = decode_lsb(stego_path, password)

        self.decode_button.config(state='normal')

        self.extracted_text_widget.config(state='normal')
        self.extracted_text_widget.delete("1.0", tk.END)

        if success:
            self.extracted_text_widget.insert(tk.END, message_or_data)
            messagebox.showinfo("Success", "Message extracted and decrypted successfully!")
            logging.info("Decoding successful.")
        else:
            self.extracted_text_widget.insert(tk.END, f"--- FAILED ---\n{message_or_data}")
            messagebox.showerror("Decoding Failed", message_or_data)
            logging.error(f"Decoding failed: {message_or_data}")

        self.extracted_text_widget.config(state='disabled')

if __name__ == "__main__":
    app = StegoApp()
    app.mainloop()
