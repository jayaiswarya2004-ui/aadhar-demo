import streamlit as st

st.title("Aadhaar Demo App")

# Personal info inputs
name = st.text_input("Enter your name:")
email = st.text_input("Enter your email:")
aadhaar = st.text_input("Enter Aadhaar number:")

if st.button("Encrypt & Decrypt"):
    if not aadhaar:
        st.warning("Please enter Aadhaar number!")
    else:
        # Dummy encryption (reverse string)
        encrypted = aadhaar[::-1]
        decrypted = encrypted[::-1]

        st.subheader("Author Info")
        st.write("Author: Demo Author")
        st.write("Email:", email)
        
        st.subheader("Aadhaar Encryption")
        st.write("Encrypted:", encrypted)
        st.write("Decrypted:", decrypted)
