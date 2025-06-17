AES & 3DES Parallel Encryption/Decryption Streamlit App
Overview
This Streamlit web app allows users to securely encrypt and decrypt large files using parallelized AES-256 and Triple DES (3DES) algorithms.
The app supports chunked processing, parallel execution, and key management within the session.

Features
Upload files of up to 200MB for encryption/decryption

Choose between AES-256 and 3DES encryption algorithms

Select chunk size (512 KB, 1 MB, 2 MB)

Parallel or serial processing modes

Real-time progress bars during encryption/decryption

Copyable encryption and decryption keys and initialization vectors (IV)

Verification of decrypted file against original

Installation & Running Locally
Clone this repository:

bash
Copy
git clone https://github.com/yourusername/AES_DES_Streamlit_App.git
cd AES_DES_Streamlit_App
Install dependencies:

bash
Copy
pip install -r requirements.txt
Run the app:

bash
Copy
streamlit run AES_DES.py
Deployment
This app is designed for deployment on Streamlit Community Cloud.
Push your code to GitHub and connect your repo to deploy.

Dependencies
streamlit

cryptography

psutil

License
MIT License 
