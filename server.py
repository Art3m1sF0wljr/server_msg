# === Import Section (unchanged) ===
import logging
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
import sqlite3
import os
import time
import random
import string
import binascii

# === Flask & SocketIO Initialization ===
app = Flask(__name__)
app.config['SECRET_KEY'] = '' #insert strong random key bruh
app.config['DEBUG'] = False
socketio = SocketIO(app, cors_allowed_origins="*")

# === Logging Setup ===
logging.basicConfig(level=logging.DEBUG)

# === Key Management ===
PRIVATE_KEY_FILE = "server_private_key.pem"
PUBLIC_KEY_FILE = "server_public_key.pem"

def load_or_generate_server_keys():
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "rb") as private_file:
            server_private_key = RSA.import_key(private_file.read())
        with open(PUBLIC_KEY_FILE, "rb") as public_file:
            server_public_key = RSA.import_key(public_file.read())
        logging.debug("Loaded existing server keys.")
    else:
        server_private_key = RSA.generate(2048, randfunc=os.urandom)
        server_public_key = server_private_key.publickey()

        with open(PRIVATE_KEY_FILE, "wb") as private_file:
            private_file.write(server_private_key.export_key())
        with open(PUBLIC_KEY_FILE, "wb") as public_file:
            public_file.write(server_public_key.export_key())
        
        logging.debug("Generated new RSA server keys and saved to files.")
    
    return server_private_key, server_public_key

SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = load_or_generate_server_keys()

# === Database Setup ===
DB_FILE = "secure_messaging.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT UNIQUE,
            public_key TEXT,
            last_online TIMESTAMP
        )""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_phone TEXT,
            recipient_phone TEXT,
            encrypted_message TEXT,
            signature TEXT,
            hash TEXT,
            timestamp INTEGER,
            delivered BOOLEAN DEFAULT 0
        )""")
        conn.commit()
        logging.debug("Database initialized.")

init_db()

# === Helper Functions ===
def compute_hash(data):
    """Compute SHA-256 hash of the provided data."""
    if isinstance(data, str):
        data = data.encode()  # Encode only if the data is a string
    hasher = SHA256.new(data)
    return b64encode(hasher.digest()).decode()

def get_client(phone_number):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM clients WHERE phone_number = ?", (phone_number,))
        result = cursor.fetchone()
        logging.debug(f"Fetched client {phone_number}: {result}")
        return result

def store_message(sender, recipient, message, signature, message_hash):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO messages (sender_phone, recipient_phone, encrypted_message, signature, hash, timestamp, delivered)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        """, (sender, recipient, message, signature, message_hash, int(time.time())))
        conn.commit()

def get_undelivered_messages(phone_number):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sender_phone, encrypted_message, signature, hash FROM messages
            WHERE recipient_phone = ? AND delivered = 0
        """, (phone_number,))
        result = cursor.fetchall()
        logging.debug(f"Undelivered messages fetched for {phone_number}: {result}")
        return result

def mark_messages_as_delivered(phone_number):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE messages SET delivered = 1 WHERE recipient_phone = ?
        """, (phone_number,))
        conn.commit()

# === Endpoints with Hash Verification ===
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    public_key = data.get("public_key")
    encrypted_phone = b64decode(data.get("encrypted_phone"))
    received_hash = data.get("hash")

    # Verify integrity of the encrypted phone number
    computed_hash = compute_hash(encrypted_phone)
    if received_hash != computed_hash:
        return jsonify({"status": "error", "message": "Data integrity check failed."}), 400

    # Decrypt the phone number using the server's private key
    cipher = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)
    try:
        phone_number = cipher.decrypt(encrypted_phone).decode()
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return jsonify({"status": "error", "message": "Invalid encrypted data."}), 400

    # Check if the phone number is already registered
    if get_client(phone_number):
        return jsonify({"status": "error", "message": "Phone number already registered."}), 400

    # Store the client's public key and phone number
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO clients (phone_number, public_key) VALUES (?, ?)", (phone_number, public_key))
        conn.commit()
    
    logging.debug(f"Registered client {phone_number} with public key: {public_key}")
    return jsonify({"status": "success", "message": "Registration successful."})
    
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    encrypted_phone = b64decode(data.get("phone_number"))
    received_hash = data.get("hash")

    # Verify integrity of the encrypted phone number
    computed_hash = compute_hash(encrypted_phone)
    if received_hash != computed_hash:
        return jsonify({"status": "error", "message": "Data integrity check failed."}), 400

    # Decrypt the phone number using the server's private key
    cipher = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)
    try:
        phone_number = cipher.decrypt(encrypted_phone).decode()
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return jsonify({"status": "error", "message": "Invalid encrypted data."}), 400

    # Check if the client is registered
    client = get_client(phone_number)
    if not client:
        return jsonify({"status": "error", "message": "Client not registered."}), 404

    # Generate a challenge and encrypt it with the client's public key
    challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    public_key = RSA.import_key(client[0])
    encrypted_challenge = PKCS1_OAEP.new(public_key).encrypt(challenge.encode())

    # Compute hash of the ENCRYPTED challenge for integrity verification
    challenge_hash = compute_hash(encrypted_challenge)
    app.config[phone_number] = challenge  # Store the challenge for later verification

    return jsonify({
        "challenge": b64encode(encrypted_challenge).decode(),
        "hash": challenge_hash
    })
    
@app.route("/verify", methods=["POST"])
def verify():
    data = request.json

    # Decode the Base64-encoded phone number
    try:
        phone_number = b64decode(data.get("phone_number")).decode()
    except binascii.Error as e:
        logging.error(f"Base64 decoding failed: {e}")
        return jsonify({"status": "error", "message": "Invalid phone number format."}), 400
    except Exception as e:
        logging.error(f"Unexpected error during Base64 decoding: {e}")
        return jsonify({"status": "error", "message": "Invalid data format."}), 400

    encrypted_response = b64decode(data.get("encrypted_response"))
    signature = b64decode(data.get("signature"))
    received_hash = data.get("hash")

    # Verify integrity of the encrypted response
    computed_hash = compute_hash(encrypted_response)
    if received_hash != computed_hash:
        return jsonify({"status": "error", "message": "Data integrity check failed."}), 400

    # Retrieve the original challenge
    original_challenge = app.config.get(phone_number)
    if not original_challenge:
        return jsonify({"status": "error", "message": "No challenge found."}), 400

    # Decrypt the response using the server's private key
    cipher = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)
    try:
        decrypted_response = cipher.decrypt(encrypted_response).decode()
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return jsonify({"status": "error", "message": "Invalid encrypted data."}), 400

    # Verify the challenge response
    if decrypted_response != original_challenge:
        return jsonify({"status": "error", "message": "Invalid challenge response."}), 401

    # Verify the signature
    client = get_client(phone_number)
    client_public_key = RSA.import_key(client[0])
    h = SHA256.new(decrypted_response.encode())
    try:
        pkcs1_15.new(client_public_key).verify(h, signature)

        # Check for undelivered messages
        undelivered_count = len(get_undelivered_messages(phone_number))
        return jsonify({
            "status": "success",
            "message": "Authentication successful.",
            "undelivered_count": undelivered_count
        })
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Signature verification failed."}), 401

@app.route("/send-message", methods=["POST"])
def send_message():
    data = request.json
    sender = b64decode(data.get("sender_phone")).decode()
    recipient = b64decode(data.get("recipient_phone")).decode()
    encrypted_message = b64decode(data.get("encrypted_message"))
    signature = b64decode(data.get("signature"))
    received_hash = data.get("hash")

    # Log the encrypted message and its hash
    logging.debug(f"Received encrypted message: {b64encode(encrypted_message).decode()}")
    logging.debug(f"Received hash: {received_hash}")
    logging.debug(f"Computed hash: {compute_hash(encrypted_message)}")

    computed_hash = compute_hash(encrypted_message)
    if received_hash != computed_hash:
        return jsonify({"status": "error", "message": "Data integrity compromised."}), 400

    if not get_client(recipient):
        return jsonify({"status": "error", "message": "Recipient not found."}), 404

    store_message(sender, recipient, b64encode(encrypted_message).decode(), b64encode(signature).decode(), received_hash)
    logging.debug(f"Message from {sender} to {recipient} successfully stored.")
    return jsonify({"status": "success", "message": "Message stored successfully."})

@app.route("/get-messages", methods=["POST"])
def get_messages():
    data = request.json
    phone_number = data.get("phone_number")
    messages = get_undelivered_messages(phone_number)

    # Mark messages as delivered after fetching them
    mark_messages_as_delivered(phone_number)

    return jsonify({"messages": messages})

@app.route("/get-public-key", methods=["GET", "POST"])
def get_public_key():
    data = request.json if request.method == "POST" else request.args
    phone_number = data.get("phone_number", "").strip()  # Handle both POST and GET

    if not phone_number:  # No phone number provided, return server's public key
        logging.debug("Returning server's public key.")
        return jsonify({"public_key": SERVER_PUBLIC_KEY.export_key().decode()})

    # If phone number is provided, return the client's public key
    logging.debug(f"Received request for public key of {phone_number}")
    client = get_client(phone_number)

    if not client:
        logging.error(f"Client {phone_number} not found.")
        return jsonify({"status": "error", "message": "Client not found."}), 404

    return jsonify({"public_key": client[0]})


        
# === SocketIO Events ===
@socketio.on("register_online")
def register_online(phone_number):
    emit("status", {"message": f"{phone_number} is online."}, broadcast=True)

@socketio.on("register_offline")
def register_offline(phone_number):
    emit("status", {"message": f"{phone_number} is offline."}, broadcast=True)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=21)
