import streamlit as st
from kyber import Kyber512
from dilithium import Dilithium2

# Initialize Kyber and Dilithium
kyber = Kyber512()
dilithium = Dilithium2()

# Streamlit UI
st.title("Post-Quantum Cryptography Demo")

# Step 1: Input Aadhaar Number
aadhaar = st.text_input("Enter Aadhaar Number:")

if aadhaar:
    # Step 2: Encrypt using Kyber
    ciphertext, shared_secret = kyber.encrypt(aadhaar.encode())

    # Step 3: Sign using Dilithium
    signature = dilithium.sign(shared_secret)

    # Display results
    st.write("Encrypted Aadhaar:", ciphertext)
    st.write("Shared Secret:", shared_secret)
    st.write("Digital Signature:", signature)

    # Verification
    if dilithium.verify(shared_secret, signature):
        st.success("Signature Verified Successfully!")
    else
