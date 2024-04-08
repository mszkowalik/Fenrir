from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os
import datetime
import base64
import os

app = Flask(__name__)

# CA certificate and key paths
CA_CERT_PATH = os.environ['CA_CERT_PATH']
CA_KEY_PATH = os.environ['CA_KEY_PATH']

# Load CA credentials
try:
    with open(CA_CERT_PATH, "rb") as cert_file:
        ca_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
    with open(CA_KEY_PATH, "rb") as key_file:
        ca_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())
except FileNotFoundError as e:
    print(f"Error: {e}")
    exit(1)

def sanitize_filename(filename):
    """Sanitize the filename to prevent directory traversal or illegal characters."""
    return "".join([c for c in filename if c.isalpha() or c.isdigit() or c in ('_', '-')]).rstrip()

@app.route('/generate_cert', methods=['POST'])
def generate_cert():
    data = request.json
    device_name = sanitize_filename(data['device_name'])
    valid_for = int(data['valid_for'])

    # Generate key pair for the device
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build certificate for the device
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, device_name),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=valid_for)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256())

    certs_issued_dir = '/certs/issued'
    os.makedirs(certs_issued_dir, exist_ok=True)

    # Serialize and save the device key and certificate
    cert_path = certs_issued_dir + '/' + device_name + '.crt'
    key_path = certs_issued_dir + '/' + device_name + '.key'
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return jsonify({'message': 'Certificate generated successfully.'})

@app.route('/getTLSKey', methods=['POST'])
def get_tls_key():
    data = request.json
    device_name = sanitize_filename(data['device_name'])
    cert_path = f'certs/issued/{device_name}.crt'
    key_path = f'certs/issued/{device_name}.key'

    # Check if the certificate exists, if not, generate it
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        # Assuming default validity of 365 days if not specified
        valid_for = data.get('valid_for', 365)
        generate_cert(valid_for, device_name)

    # Load and process the private key and certificate to get TLSKey values
    with open(key_path, 'rb') as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    with open(cert_path, 'rb') as cert_file:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    tlskey1 = base64.b64encode(private_key_der).decode('utf-8')

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    tlskey2 = base64.b64encode(cert_der).decode('utf-8')

    return jsonify({'TLSKey1': f'TLSKey1 {tlskey1}', 'TLSKey2': f'TLSKey2 {tlskey2}'})

if __name__ == '__main__':
    app.run(debug=True)
