Python 3.10.5 (tags/v3.10.5:f377153, Jun  6 2022, 16:14:13) [MSC v.1929 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license()" for more information.
import streamlit as st
import numpy as np

st.title("Aadhaar Demo App – PQC (Kyber Simulation)")

# --- Step 1: Basic Info ---
st.header("Step 1: Enter Your Basic Info")
name = st.text_input("Enter your Name:")
email = st.text_input("Enter your Email:")
aadhaar = st.text_input("Enter Aadhaar Number:")

st.markdown("---")

# --- Step 2: Encrypt & Decrypt (Kyber Simulation) ---
st.header("Step 2: Encrypt & Decrypt Aadhaar")

# Kyber-like simple lattice encryption (simulation)
def kyber_encrypt(message, key=17, q=3329):
    # convert string to numbers (ASCII)
    nums = [ord(c) for c in message]
    # encryption = (nums * key) mod q
    enc = [(n * key) % q for n in nums]
    return enc

def kyber_decrypt(enc, key=17, q=3329):
    # decryption = round(enc / key) (inverse operation)
    dec = [round(e / key) for e in enc]
    message = ''.join([chr(d) for d in dec])
    return message

if aadhaar:
    if st.button("Encrypt & Decrypt"):
        encrypted = kyber_encrypt(aadhaar)
        decrypted = kyber_decrypt(encrypted)

        st.write("🔒 Encrypted Aadhaar:", encrypted)
        st.write("🔑 Decrypted Aadhaar:", decrypted)
else:
    st.write("Please enter Aadhaar number in Step 1.")

st.markdown("---")

# --- Step 3: Verification ---
st.header("Step 3: Verification")
if aadhaar:
    if int(aadhaar[-1]) % 2 == 0:
        verification = "✅ Verified"
    else:
        verification = "❌ Not Verified"
    st.write("Verification Result:", verification)
else:
    st.write("Please enter Aadhaar number in Step 1.")
