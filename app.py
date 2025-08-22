from flask import Flask, render_template, request, redirect, url_for
from util import encode_message, decode_message, encrypt_message, decrypt_message
from PIL import Image
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'static/encoded_images'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/encode', methods=['POST'])
def encode():
    image_file = request.files['image']
    message = request.form['message']
    password = request.form['pwd']
    image = Image.open(image_file)

    # Encrypt the message if password provided
    if password.strip():
        message = encrypt_message(message, password)

    output_filename = 'encoded_image.png'
    output_path = os.path.join(UPLOAD_FOLDER, output_filename)
    encode_message(image, message, output_path)

    image_url = url_for('static', filename=f'encoded_images/{output_filename}')
    return render_template('result.html', image_url=image_url)

@app.route('/decode', methods=['POST'])
def decode():
    password = request.form['pwd']
    image_file = request.files['image']
    image = Image.open(image_file)

    try:
        hidden_data = decode_message(image)
        if password.strip():
            try:
                message = decrypt_message(hidden_data, password)
            except Exception as e:
                message = f"Failed to decrypt message: {str(e)}"
        else:
            message = hidden_data
    except Exception as e:
        message = f"Error decoding message: {str(e)}"

    return f"<h2>Decoded Message:</h2><p>{message}</p>"

if __name__ == '__main__':
    app.run(debug=True)
