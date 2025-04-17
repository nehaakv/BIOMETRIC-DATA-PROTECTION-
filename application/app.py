from flask import Flask, request, render_template, jsonify, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import numpy as np
import cv2
import csv
import qrcode
import os

# Initialize Flask app
app = Flask(__name__)

# Set the file upload folder
UPLOAD_FOLDER = './web_app/uploads'
STATIC_FOLDER = './web_app/static'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# AES Encryption Function
def aes_encrypt(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return iv, ciphertext

# Embed encrypted message into an image using LSB
def embed_message_into_image(image_path, iv, ciphertext):
    message = iv + ciphertext
    binary_message = ''.join(format(byte, '08b') for byte in message)
    img = cv2.imread(image_path)
    height, width, _ = img.shape
    flat_img = img.flatten()

    if len(binary_message) > len(flat_img):
        raise ValueError("Message is too large to embed in this image.")

    for i in range(len(binary_message)):
        flat_img[i] = (flat_img[i] & 0xFE) | int(binary_message[i])

    img_with_message = flat_img.reshape((height, width, 3))
    output_image_path = os.path.join(STATIC_FOLDER, 'image_with_message.png')
    cv2.imwrite(output_image_path, img_with_message)
    return output_image_path

# QR Code generation
def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    qr_img = qr.make_image(fill="black", back_color="white")
    qr_path = os.path.join(STATIC_FOLDER, "ENC.png")
    qr_img.save(qr_path)
    return qr_path

# AES Decryption Function
def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    return plaintext

# Extract message from image using LSB
def extract_message_from_image(image_path,key,original_iv, original_ciphertext):
    img = cv2.imread(image_path)
    height, width, _ = img.shape
    
    # Flatten the image to make it easier to manipulate pixel values
    flat_img = img.flatten()
    
    # Extract the binary message from the LSB of the pixels
    extracted_bits = []
    for pixel_value in flat_img:
        extracted_bits.append(str(pixel_value & 1))  # Get the LSB of each pixel
    
    # Combine the bits to form the binary message
    binary_message = ''.join(extracted_bits)
    
    # Calculate the expected length in bits
    expected_length = (len(original_iv) + len(original_ciphertext)) * 8  # IV + ciphertext length in bits
    
    # Extract only the required bits
    binary_message = binary_message[:expected_length]
    
    # Convert binary message back to bytes
    extracted_bytes = bytearray()
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        extracted_bytes.append(int(byte, 2))
    iv = bytes(extracted_bytes[:16])  # First 16 bytes are the IV
    ciphertext = bytes(extracted_bytes[16:])  # Remaining bytes are the ciphertext
    
    return iv, ciphertext

# Home Route
@app.route('/')
def index():
    return render_template('index.html')

# Encrypt Route
@app.route('/encrypt', methods=['POST'])
def encrypt():
    csv_file = request.files['csv_file']
    image_file = request.files['image_file']
    
    # Save the uploaded files
    csv_path = os.path.join(UPLOAD_FOLDER, csv_file.filename)
    image_path = os.path.join(UPLOAD_FOLDER, image_file.filename)

    csv_file.save(csv_path)
    image_file.save(image_path)

    # Read the first row of the CSV file
    with open(csv_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip header row
        first_row = next(reader)
        plaintext = ','.join(first_row)

    # Generate a random AES key (256-bit)
    key = get_random_bytes(32)
    
    # Encrypt the plaintext
    iv, ciphertext = aes_encrypt(key, plaintext)
    
    # Embed the encrypted message into the image
    encrypted_image_path = embed_message_into_image(image_path, iv, ciphertext)
    
    # Generate QR code with key and IV
    qr_data = f"Key: {key.hex()}\nIV: {iv.hex()}\nCiphertext: {ciphertext.hex()}"
    qr_path = generate_qr_code(qr_data)

    # Pass the AES key, IV, ciphertext, encrypted image path, and QR code path to the template
    return render_template(
        'encrypt.html',
        key=key.hex(),
        iv=iv.hex(),
        ciphertext=ciphertext.hex(),
        encrypted_image_path=encrypted_image_path,
        qr_path=qr_path
    )

# Decrypt Route
@app.route('/decrypt', methods=['POST'])
def decrypt():
    image_file = request.files['image_file']
    key_hex = request.form['key']
    iv_hex = request.form['iv']
    ciphertext_hex = request.form['ciphertext']

    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    image_path = os.path.join(UPLOAD_FOLDER, image_file.filename)
    image_file.save(image_path)

    try:
        # Extract the message (IV and Ciphertext) from the image
        extracted_iv, extracted_ciphertext = extract_message_from_image(image_path,key,iv,ciphertext)

        # Debugging: Print extracted IV and ciphertext
        print(f"Extracted IV: {extracted_iv.hex()}")
        print(f"Extracted Ciphertext: {extracted_ciphertext.hex()}")

        # Check if extracted data matches the original
        if extracted_iv == iv and extracted_ciphertext == ciphertext:
            decrypted_message = aes_decrypt(key, iv, ciphertext)
            message_status = "The extracted contents match the original data."
        else:
            decrypted_message = "The extracted contents do not match the provided data."
            message_status = "Error: Mismatch in extracted and provided data."
        
        return render_template('decrypt.html', message=decrypted_message, message_status=message_status)
    except Exception as e:
        return render_template('error.html', error=str(e))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
