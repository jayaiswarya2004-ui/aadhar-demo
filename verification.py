import streamlit as st

st.title("Aadhaar Demo App – Multi-step")

# --- Page 1: Basic Info ---
st.header("Step 1: Enter Your Basic Info")
name = st.text_input("Enter your Name:")
email = st.text_input("Enter your Email:")
aadhaar = st.text_input("Enter Aadhaar Number:")

st.markdown("---")  # separator

# --- Page 2: Encrypt & Decrypt ---
st.header("Step 2: Encrypt & Decrypt Aadhaar")
if aadhaar:
    if st.button("Encrypt & Decrypt"):
        # Replace this with your lattice-based encryption logic
        encrypted = aadhaar[::-1]
        decrypted = encrypted[::-1]
        st.write("Encrypted:", encrypted)
        st.write("Decrypted:", decrypted)
else:
    st.write("Please enter Aadhaar number in Step 1.")

st.markdown("---")  # separator

# --- Page 3: Verification ---
st.header("Step 3: Verification")
if aadhaar:
    # Dummy verification logic
    if int(aadhaar[-1]) % 2 == 0:
        verification = "Verified"
    else:
        verification = "Not Verified"
    st.write("Verification Result:", verification)
else:
    st.write("Please enter Aadhaar number in Step 1.")
