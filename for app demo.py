import streamlit as st
import numpy as np

st.title("Aadhaar Encryption Demo")

aadhaar = st.text_input("Enter Aadhaar Number:")

if st.button("Encrypt & Decrypt"):
    data = np.array([int(x) for x in aadhaar])
    if len(data) % 2 != 0:
        data = np.append(data, 0)

    key = np.array([[2, 1], [1, 1]])
    data_matrix = data.reshape(-1, 2)

    encrypted = np.dot(data_matrix, key)

    key_inv = np.linalg.inv(key)
    decrypted = np.dot(encrypted, key_inv).astype(int).flatten()
    decrypted = decrypted[:len(aadhaar)]
    aadhaar_decrypted = ''.join(str(x) for x in decrypted)

    st.write("**Encrypted:**", encrypted)
    st.write("**Decrypted:**", aadhaar_decrypted)

