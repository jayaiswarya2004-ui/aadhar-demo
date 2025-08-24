import streamlit as st
from kyber import Kyber512
from dilithium import Dilithium2

# Initialize Kyber and Dilithium
kyber = Kyber512()
dilithium = Dilithium2()

st.title("Post-Quantum Cryptography Aadhaar Demo")

# Step 1: Input Aadhaar
aadhaar = st.text_input("Enter Aadhaar Number:")

if aadhaar:
    if st.button("Encrypt and Sign"):
        # Encrypt Aadhaar using Kyber
        ciphertext, shared_secret = kyber.encrypt(aadhaar.encode())

        # Sign shared secret using Dilithium
        signature = dilithium.sign(shared_secret)

        # Display outputs
        st.write("🔒 Encrypted Aadhaar:", ciphertext)
        st.write("🔑 Shared Secret:", shared_secret)
        st.write("✍ Digital Signature:", signature)

        # Verify signature
        if dilithium.verify(shared_secret, signature):
            st.success("✅ Signature Verified Successfully!")
        else:
            st.error("❌ Verification Failed!")
else:
    st.info("Please enter Aadhaar number to continue.")
