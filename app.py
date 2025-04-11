import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# 🌟 UI Improvements
st.set_page_config(page_title="Secure Vault", page_icon="🔐", layout="centered")

# Generate or store a Fernet key once
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
fernet = Fernet(st.session_state.fernet_key)

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Initialize storage in session_state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

#  App Title
st.markdown("<h1 style='text-align: center; color: #4CAF50;'>Ahsan's Secure Vault</h1>", unsafe_allow_html=True)

#  Sidebar Menu
menu = st.sidebar.radio("📂 Choose Option", ["🏠 Home", "📥 Insert Data", "📤 Retrieve Data", "🗑️ Delete Data"])

# Home Section
if menu == "🏠 Home":
    st.markdown("### Welcome to your personal encrypted storage!")
    st.info("You can safely store, view, and delete your secret text.")

# Insert Data Section
elif menu == "📥 Insert Data":
    st.subheader("Store New Data")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")
    text = st.text_area("Enter your secret text")

    if st.button("Store"):
        if st.session_state.failed_attempts < 3:
            if username and passkey and text:
                encrypted = fernet.encrypt(text.encode()).decode()
                hashed = hash_passkey(passkey)
                st.session_state.stored_data[username] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed
                }
                st.success("✅ Data stored successfully!")
            else:
                st.warning("⚠️ Please fill in all fields.")
        else:
            st.error("❌ Too many failed attempts. Please try again later.")

# Retrieve Data Section
elif menu == "📤 Retrieve Data":
    st.subheader("Retrieve Your Data")
    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Retrieve"):
        if st.session_state.failed_attempts < 3:
            if username in st.session_state.stored_data:
                stored = st.session_state.stored_data[username]
                if stored["passkey"] == hash_passkey(passkey):
                    decrypted = fernet.decrypt(stored["encrypted_text"].encode()).decode()
                    st.success("✅ Data decrypted successfully!")
                    st.code(decrypted)
                else:
                    st.session_state.failed_attempts += 1
                    st.error(f"❌ Incorrect passkey. {3 - st.session_state.failed_attempts} attempts left.")
            else:
                st.error("❌ No data found for this user.")
        else:
            st.error("❌ Too many failed attempts. Please try again later.")

# Delete Data Section
elif menu == "🗑️ Delete Data":
    st.subheader(" Delete Your Data")
    username = st.text_input("Username", key="del_user")
    passkey = st.text_input("Passkey", type="password", key="del_pass")

    if st.button("Delete"):
        if st.session_state.failed_attempts < 3:
            if username in st.session_state.stored_data:
                stored = st.session_state.stored_data[username]
                if stored["passkey"] == hash_passkey(passkey):
                    del st.session_state.stored_data[username]
                    st.success("🧹 Your data has been deleted!")
                else:
                    st.session_state.failed_attempts += 1
                    st.error(f"❌ Incorrect passkey. {3 - st.session_state.failed_attempts} attempts left.")
            else:
                st.error("❌ No data found for this user.")
        else:
            st.error("❌ Too many failed attempts. Please try again later.")