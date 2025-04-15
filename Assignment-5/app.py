import streamlit as st
import hashlib
import json
import os
import bcrypt
from cryptography.fernet import Fernet
import time

# ------------------------ 🔑 Load or Generate Persistent Key ------------------------
KEY_FILE = "secret.key"

def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

# Load the encryption key
KEY = load_or_generate_key()
cipher = Fernet(KEY)
# ------------------------------------------------------------------------------------

# File paths for storing data and user data
DATA_FILE = "data.json"
USER_FILE = "users.json"

# Time-based lockout configuration
LOCKOUT_TIME = 30  # seconds
MAX_FAILED_ATTEMPTS = 3

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0
if "lockout_time" not in st.session_state:
    st.session_state["lockout_time"] = None
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
    st.session_state["current_user"] = None

# Function to load stored data
def load_data(file_path):
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            return {}
    return {}

# Function to save data
def save_data(file_path, data):
    with open(file_path, "w") as file:
        json.dump(data, file)

# Load existing data and users
stored_data = load_data(DATA_FILE)
users_data = load_data(USER_FILE)

# Hash password
def hash_passkey(passkey):
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), b'salt', 100000).hex()

# Check password
def check_passkey(stored_hash, passkey):
    return stored_hash == hashlib.pbkdf2_hmac('sha256', passkey.encode(), b'salt', 100000).hex()

# Encrypt
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Decrypt
def decrypt_data(encrypted_text, passkey):
    for label, value in stored_data.get(st.session_state["current_user"], {}).items():
        if value["encrypted_text"] == encrypted_text:
            if check_passkey(value["passkey"], passkey):
                try:
                    decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
                    st.session_state["failed_attempts"] = 0
                    return decrypted_text
                except Exception as e:
                    st.error(f"❌ Decryption failed: {str(e)}")
                    return None
    st.session_state["failed_attempts"] += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login", "Register"]
choice = st.sidebar.selectbox("Navigation", menu)

# Login Page
def login_page():
    st.subheader("🔑 Login to your account")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    if st.session_state["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        time_left = LOCKOUT_TIME - (time.time() - st.session_state["lockout_time"])
        if time_left > 0:
            st.warning(f"🔒 Too many failed attempts! Wait {int(time_left)} seconds.")
            return

    if st.button("Login"):
        if username and password:
            if username in users_data and check_passkey(users_data[username]["password"], password):
                st.session_state["logged_in"] = True
                st.session_state["current_user"] = username
                st.success("✅ Login successful!")
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect username or password!")
                st.session_state["failed_attempts"] += 1
                if st.session_state["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
                    st.session_state["lockout_time"] = time.time()
        else:
            st.error("⚠️ Fill in both fields.")

    st.write("🔑 New User? Please **Register First** below.")
    if st.button("Go to Register Page"):
        st.session_state["logged_in"] = False
        st.experimental_rerun()

# Register Page
def register_page():
    st.subheader("📋 Create an Account")
    username = st.text_input("Choose a Username:")
    password = st.text_input("Choose a Password:", type="password")
    confirm_password = st.text_input("Confirm Password:", type="password")

    if st.button("Register"):
        if username and password and confirm_password:
            if password == confirm_password:
                if username in users_data:
                    st.error("❌ Username already exists!")
                else:
                    hashed_password = hash_passkey(password)
                    users_data[username] = {"password": hashed_password}
                    save_data(USER_FILE, users_data)
                    st.success("✅ Account created! You can now login.")
            else:
                st.error("❌ Passwords do not match!")
        else:
            st.error("⚠️ Fill in all fields.")

# Home Page
def home_page():
    st.subheader("🏠 Welcome")
    st.write("Securely **store and retrieve data** using a passkey.")
    st.write(f"Logged in as: {st.session_state['current_user']}")

# Store Data Page
def store_data_page():
    if not st.session_state["logged_in"]:
        st.warning("⚠️ Please log in first.")
        return

    st.subheader("📂 Store Data Securely")
    label = st.text_input("Label:")
    user_data = st.text_area("Data:")
    passkey = st.text_input("Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if label and user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            if st.session_state["current_user"] not in stored_data:
                stored_data[st.session_state["current_user"]] = {}
            stored_data[st.session_state["current_user"]][label] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data(DATA_FILE, stored_data)
            st.success("✅ Data stored securely!")
            st.write(f"🔐 Token: `{encrypted_text}`")
        else:
            st.error("⚠️ All fields are required!")

# Retrieve Data Page
def retrieve_data_page():
    if not st.session_state["logged_in"]:
        st.warning("⚠️ Please log in first.")
        return

    st.subheader("🔍 Retrieve Data")
    token = st.text_area("Paste Token:", height=150)
    passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")

    if st.button("Decrypt"):
        if token and passkey:
            decrypted_text = None
            for label, value in stored_data.get(st.session_state["current_user"], {}).items():
                if value["encrypted_text"] == token:
                    decrypted_text = decrypt_data(token, passkey)
                    break

            if decrypted_text:
                st.success(f"✅ Decrypted Data:\n\n{decrypted_text}")
            else:
                st.error(f"❌ Incorrect token or passkey! Attempts left: {MAX_FAILED_ATTEMPTS - st.session_state['failed_attempts']}")
                if st.session_state["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Token and Passkey are required!")

# Main App Logic
if not st.session_state["logged_in"]:
    if choice == "Login":
        login_page()
    elif choice == "Register":
        register_page()
else:
    if choice == "Home":
        home_page()
    elif choice == "Store Data":
        store_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()
