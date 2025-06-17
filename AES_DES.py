import streamlit as st
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
import platform
import psutil
import threading

CHUNK_SIZES = {
    "512 KB": 512 * 1024,
    "1 MB": 1024 * 1024,
    "2 MB": 2 * 1024 * 1024,
}

def generate_keys(cipher_name):
    if cipher_name == "AES":
        key = os.urandom(32)  # AES-256
        iv = os.urandom(16)
    elif cipher_name == "DES":
        key = os.urandom(24)  # 3DES key size 192 bits
        iv = os.urandom(8)
    else:
        raise ValueError("Unsupported cipher")
    return key, iv

def encrypt_chunk_AES(data_chunk, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data_chunk) + encryptor.finalize()

def decrypt_chunk_AES(data_chunk, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data_chunk) + decryptor.finalize()

def encrypt_chunk_DES(data_chunk, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data_chunk) + encryptor.finalize()

def decrypt_chunk_DES(data_chunk, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data_chunk) + decryptor.finalize()

def split_bytes(data_bytes, chunk_size):
    for i in range(0, len(data_bytes), chunk_size):
        yield data_bytes[i:i+chunk_size]

def encrypt_wrapper_AES(args):
    return encrypt_chunk_AES(*args)

def decrypt_wrapper_AES(args):
    return decrypt_chunk_AES(*args)

def encrypt_wrapper_DES(args):
    return encrypt_chunk_DES(*args)

def decrypt_wrapper_DES(args):
    return decrypt_chunk_DES(*args)

def process_data(data_bytes, chunk_size, key, iv, cipher_name, mode, parallel=True, progress_callback=None):
    chunks = list(split_bytes(data_bytes, chunk_size))
    cpu_cores = multiprocessing.cpu_count()
    args_list = [(chunk, key, iv) for chunk in chunks]

    if cipher_name == "AES":
        encrypt_func = encrypt_wrapper_AES
        decrypt_func = decrypt_wrapper_AES
    else:
        encrypt_func = encrypt_wrapper_DES
        decrypt_func = decrypt_wrapper_DES

    func = encrypt_func if mode == "Encrypt" else decrypt_func

    total_chunks = len(args_list)
    processed_chunks = []

    if parallel:
        with ProcessPoolExecutor() as executor:
            futures = executor.map(func, args_list)
            for i, chunk in enumerate(futures, 1):
                processed_chunks.append(chunk)
                if progress_callback:
                    progress_callback(i / total_chunks)
    else:
        for i, arg in enumerate(args_list, 1):
            processed_chunks.append(func(arg))
            if progress_callback:
                progress_callback(i / total_chunks)

    processed_bytes = b''.join(processed_chunks)
    return processed_bytes, cpu_cores

def verify_files(original_bytes, decrypted_bytes):
    return original_bytes == decrypted_bytes

def show_system_info():
    st.write("### System & Algorithm Info")
    cols = st.columns(2)

    with cols[0]:
        st.subheader("AES")
        st.write("- Key size: 256 bits")
        st.write("- Block size: 128 bits")
        st.write("- Mode: CFB")

    with cols[1]:
        st.subheader("3DES")
        st.write("- Key size: 192 bits (3 x 64-bit keys)")
        st.write("- Block size: 64 bits")
        st.write("- Mode: CFB")

    st.write("### System Info")
    cpu_count = psutil.cpu_count(logical=False)
    cpu_count_logical = psutil.cpu_count(logical=True)
    st.metric("Physical CPU cores", cpu_count)
    st.metric("Logical CPU cores", cpu_count_logical)
    st.write(f"Processor: {platform.processor()}")
    st.write(f"System: {platform.system()} {platform.release()}")

def main():
    st.set_page_config(page_title="Parallel AES & 3DES Encryption/Decryption", layout="wide")

    st.title("🔒 Parallel AES & 3DES Encryption / Decryption")
    show_system_info()
    st.markdown("---")

    encrypt_col, decrypt_col = st.columns(2)

    with encrypt_col:
        st.header("Encryption")

        uploaded_file_enc = st.file_uploader("Upload file to encrypt", type=None, key="enc_file")
        cipher_name_enc = st.selectbox("Choose Cipher Algorithm", ["AES", "DES"], key="enc_cipher")
        with st.expander("Advanced Encryption Options", expanded=False):
            chunk_size_label_enc = st.selectbox("Choose Chunk Size", list(CHUNK_SIZES.keys()), key="enc_chunk")
            execution_mode_enc = st.radio("Execution Mode", ["Parallel", "Serial"], key="enc_exec_mode")

        if uploaded_file_enc:
            file_bytes_enc = uploaded_file_enc.read()
            st.write(f"File size: {len(file_bytes_enc) / 1024 / 1024:.2f} MB")

            key_name_enc = f"key_{cipher_name_enc}"

            if key_name_enc not in st.session_state:
                key_enc, iv_enc = generate_keys(cipher_name_enc)
                st.session_state[key_name_enc] = key_enc
                st.session_state[f"iv_{cipher_name_enc}"] = iv_enc
            else:
                key_enc = st.session_state[key_name_enc]
                iv_enc = st.session_state[f"iv_{cipher_name_enc}"]

            # Display key and IV with copy button inside collapsible
            with st.expander("Encryption Key & IV (hex)", expanded=False):
                col1, col2 = st.columns([4,1])
                col1.code(key_enc.hex(), language='text')
                if col2.button("Copy Key", key="copy_key_enc"):
                    st.experimental_set_clipboard(key_enc.hex())
                    st.success("Encryption Key copied to clipboard!")
                col1, col2 = st.columns([4,1])
                col1.code(iv_enc.hex(), language='text')
                if col2.button("Copy IV", key="copy_iv_enc"):
                    st.experimental_set_clipboard(iv_enc.hex())
                    st.success("Encryption IV copied to clipboard!")

            st.write(f"Key length: {len(key_enc) * 8} bits | IV length: {len(iv_enc) * 8} bits")

            encrypt_btn = st.button("Encrypt File", key="encrypt_button")

            if encrypt_btn:
                progress_bar = st.progress(0)
                status_text = st.empty()
                encrypted_bytes = b''
                try:
                    def update_progress(progress):
                        progress_bar.progress(progress)
                        status_text.text(f"Encryption progress: {int(progress*100)}%")

                    encrypted_bytes, cpu_cores_used_enc = process_data(
                        file_bytes_enc, CHUNK_SIZES[chunk_size_label_enc], key_enc, iv_enc,
                        cipher_name_enc, "Encrypt",
                        parallel=(execution_mode_enc == "Parallel"),
                        progress_callback=update_progress,
                    )

                    st.success(f"Encryption done using {cpu_cores_used_enc} cores.")
                    st.download_button(
                        label="Download Encrypted File",
                        data=encrypted_bytes,
                        file_name=uploaded_file_enc.name + ".enc",
                        mime="application/octet-stream"
                    )
                    st.session_state['last_plaintext'] = file_bytes_enc
                    progress_bar.empty()
                    status_text.empty()
                except Exception as e:
                    st.error(f"Encryption error: {e}")

    with decrypt_col:
        st.header("Decryption")

        uploaded_file_dec = st.file_uploader("Upload file to decrypt", type=None, key="dec_file")
        original_file_for_verif = st.file_uploader(
            "Upload original file for verification (optional)", type=None, key="verif_file"
        )
        cipher_name_dec = st.selectbox("Choose Cipher Algorithm", ["AES", "DES"], key="dec_cipher")
        with st.expander("Advanced Decryption Options", expanded=False):
            chunk_size_label_dec = st.selectbox("Choose Chunk Size", list(CHUNK_SIZES.keys()), key="dec_chunk")
            execution_mode_dec = st.radio("Execution Mode", ["Parallel", "Serial"], key="dec_exec_mode")

        if uploaded_file_dec:
            file_bytes_dec = uploaded_file_dec.read()
            st.write(f"File size: {len(file_bytes_dec) / 1024 / 1024:.2f} MB")

            key_name_dec = f"key_{cipher_name_dec}"

            if key_name_dec not in st.session_state or f"iv_{cipher_name_dec}" not in st.session_state:
                st.warning("No encryption key and IV found for this cipher. Please perform encryption first or provide keys.")
            else:
                key_dec = st.session_state[key_name_dec]
                iv_dec = st.session_state[f"iv_{cipher_name_dec}"]

                # Display key and IV with copy buttons
                with st.expander("Decryption Key & IV (hex)", expanded=False):
                    col1, col2 = st.columns([4,1])
                    col1.code(key_dec.hex(), language='text')
                    if col2.button("Copy Key", key="copy_key_dec"):
                        st.experimental_set_clipboard(key_dec.hex())
                        st.success("Decryption Key copied to clipboard!")
                    col1, col2 = st.columns([4,1])
                    col1.code(iv_dec.hex(), language='text')
                    if col2.button("Copy IV", key="copy_iv_dec"):
                        st.experimental_set_clipboard(iv_dec.hex())
                        st.success("Decryption IV copied to clipboard!")

                decrypt_btn = st.button("Decrypt File", key="decrypt_button")

                if decrypt_btn:
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    decrypted_bytes = b''
                    try:
                        def update_progress(progress):
                            progress_bar.progress(progress)
                            status_text.text(f"Decryption progress: {int(progress*100)}%")

                        decrypted_bytes, cpu_cores_used_dec = process_data(
                            file_bytes_dec, CHUNK_SIZES[chunk_size_label_dec], key_dec, iv_dec,
                            cipher_name_dec, "Decrypt",
                            parallel=(execution_mode_dec == "Parallel"),
                            progress_callback=update_progress,
                        )
                        st.success(f"Decryption done using {cpu_cores_used_dec} cores.")

                        # Fix filename: remove .enc extension if present
                        filename_dec = uploaded_file_dec.name
                        if filename_dec.endswith(".enc"):
                            filename_dec = filename_dec[:-4]

                        st.download_button(
                            label="Download Decrypted File",
                            data=decrypted_bytes,
                            file_name=filename_dec,
                            mime="text/plain"
                        )

                        original_bytes = None
                        if original_file_for_verif is not None:
                            original_bytes = original_file_for_verif.read()
                        elif 'last_plaintext' in st.session_state:
                            original_bytes = st.session_state['last_plaintext']

                        if original_bytes is not None:
                            if verify_files(original_bytes, decrypted_bytes):
                                st.success("✅ Verification passed: Decrypted file matches the original!")
                            else:
                                st.error("❌ Verification failed: Files do NOT match!")
                        else:
                            st.info("Verification skipped: Original file not provided.")

                        progress_bar.empty()
                        status_text.empty()
                    except Exception as e:
                        st.error(f"Decryption error: {e}")

if __name__ == "__main__":
    main()
