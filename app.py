from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec
import os
import datetime
import base64
import os

app = Flask(__name__)

# CA certificate and key paths
CA_CERT_PATH = os.environ['CA_CERT_PATH']
CA_KEY_PATH = os.environ['CA_KEY_PATH']

certs_issued_dir = '/certs/issued'
# Load CA credentials
try:
    with open(CA_CERT_PATH, "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read(), default_backend())
    with open(CA_KEY_PATH, "rb") as ca_key_file:
        ca_key = load_pem_private_key(ca_key_file.read(), password=None, backend=default_backend())
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
    key_type = data.get('key_type', 'RSA').upper()  # Default to RSA if not specified

    # Generate key pair for the device based on specified key type
    if key_type == 'RSA':
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == 'EC':
        key = ec.generate_private_key(ec.SECP256R1())  # Example curve
    else:
        return jsonify({'error': f'Unsupported key type: {key_type}'}), 400

    # Build certificate for the device
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, device_name),
    ])
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.utcnow())\
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=valid_for))\
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)\
        .sign(ca_key, hashes.SHA256())

    os.makedirs(certs_issued_dir, exist_ok=True)

    # Serialize and save the device key and certificate
    cert_path = os.path.join(certs_issued_dir, f'{device_name}.crt')
    key_path = os.path.join(certs_issued_dir, f'{device_name}.key')
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(key_path, 'wb') as f:
        private_key_format = serialization.PrivateFormat.PKCS8
        if key_type == 'EC':
            private_key_format = serialization.PrivateFormat.TraditionalOpenSSL
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=private_key_format,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Read the content back to return it
    with open(cert_path, 'r') as f:
        cert_content = f.read()
    with open(key_path, 'r') as f:
        key_content = f.read()
    # Serializing key and cert to PEM format and then encoding to base64
    key_pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL if key_type == 'EC' else serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    tls_key = base64.b64encode(key_pem).decode('utf-8')
    tls_cert = base64.b64encode(cert_pem).decode('utf-8')

    return jsonify({'message': 'Certificate generated successfully.',
                    'tls.key': tls_key,
                    'tls.crt': tls_cert})

@app.route('/getTLSKey', methods=['POST'])
def get_tls_key():
    data = request.json
    device_name = sanitize_filename(data['device_name'])
    cert_path = certs_issued_dir + '/' + device_name + '.crt'
    key_path = certs_issued_dir + '/' + device_name + '.key'

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

    # Ensure the loaded key is an Elliptic Curve key
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("The provided key is not an EC private key.")

    # Access the private number of the EC key
    private_number = private_key.private_numbers().private_value

    # Convert the private number to bytes
    private_number_bytes = private_number.to_bytes(
        (private_number.bit_length() + 7) // 8, # Calculate the number of bytes needed
        byteorder='big'
    )

    # Base64 encode the private number bytes
    tlskey1_base64 = base64.b64encode(private_number_bytes).decode('utf-8')

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    tlskey2_base64 = base64.b64encode(cert_der).decode('utf-8')

    return jsonify({'TLSKey1': f'TLSKey1 {tlskey1_base64}', 'TLSKey2': f'TLSKey2 {tlskey2_base64}'})

def cert_to_c_array():
    # Assuming the public key is RSA (adjust as necessary for other types)
    public_key = ca_cert.public_key()
    public_numbers = public_key.public_numbers()

    # Convert components to hex arrays
    n_array = ','.join(f'0x{x:02X}' for x in public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big'))
    e_array = ','.join(f'0x{x:02X}' for x in public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big'))

    # DN in a format similar to your example, though manual adjustment might be necessary for exact matching
    dn_bytes = ca_cert.subject.public_bytes(serialization.Encoding.DER)
    dn_array = ','.join(f'0x{x:02X}' for x in dn_bytes)

    # Generating C-like structures
    dn_c = f"static const unsigned char PROGMEM TA0_DN[] = {{{dn_array}}};\n"
    n_c = f"static const unsigned char PROGMEM TA0_RSA_N[] = {{{n_array}}};\n"
    e_c = f"static const unsigned char PROGMEM TA0_RSA_E[] = {{{e_array}}};\n"

    return dn_c, n_c, e_c

@app.route('/getCEmbedding', methods=['POST'])
def get_c_embedding():
    dn_c, n_c, e_c = cert_to_c_array()
    return jsonify({'dn_c': dn_c, 'n_c': n_c, 'e_c': e_c})

if __name__ == '__main__':
    app.run(debug=True)
