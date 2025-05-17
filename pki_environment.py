import os
import ssl
import socket
import datetime
import time
from datetime import UTC
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

OUTPUT_DIR = "pki_files"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def generate_key_pair():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return key


def save_certificate(cert, filename):
    with open(os.path.join(OUTPUT_DIR, filename), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def save_private_key(key, filename, password=None):
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    with open(os.path.join(OUTPUT_DIR, filename), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        ))

# Certificate Authority
def create_ca():
    try:
        ca_key = generate_key_pair()
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "MyCA Root"),
        ])
        ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(UTC)
        ).not_valid_after(
            datetime.datetime.now(UTC) + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(ca_key, hashes.SHA256(), default_backend())
        
        save_certificate(ca_cert, "ca_cert.pem")
        save_private_key(ca_key, "ca_key.pem")
        print("CA certificate and key created successfully")
        return ca_key, ca_cert
    except Exception as e:
        print(f"Failed to create CA: {e}")
        raise

# Registration Authority
def issue_user_certificate(ca_key, ca_cert, user_name, user_email):
    user_key = generate_key_pair()
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, user_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, user_email),
    ])).sign(user_key, hashes.SHA256(), default_backend())
    
    if "@" not in user_email:
        raise ValueError("Invalid email address")
    
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(UTC)
    ).not_valid_after(
        datetime.datetime.now(UTC) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    save_certificate(cert, f"user_{user_name}_cert.pem")
    save_private_key(user_key, f"user_{user_name}_key.pem")
    return cert, user_key

def issue_website_certificate(ca_key, ca_cert, hostname):
    try:
        website_key = generate_key_pair()
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False
        ).sign(website_key, hashes.SHA256(), default_backend())
        
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(UTC)
        ).not_valid_after(
            datetime.datetime.now(UTC) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False
        ).sign(ca_key, hashes.SHA256(), default_backend())
        
        save_certificate(cert, f"{hostname}_cert.pem")
        save_private_key(website_key, f"{hostname}_key.pem")
        print(f"Certificate for {hostname} created successfully")
        return cert, website_key
    except Exception as e:
        print(f"Failed to issue certificate for {hostname}: {e}")
        raise

# Certificate Revocation List
def create_crl(ca_key, ca_cert, revoked_serials):
    crl = x509.CertificateRevocationListBuilder().issuer_name(
        ca_cert.subject
    ).last_update(
        datetime.datetime.now(UTC)
    ).next_update(
        datetime.datetime.now(UTC) + datetime.timedelta(days=30)
    )
    for serial in revoked_serials:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            serial
        ).revocation_date(
            datetime.datetime.now(UTC)
        ).build(default_backend())
        crl = crl.add_revoked_certificate(revoked_cert)
    
    crl = crl.sign(ca_key, hashes.SHA256(), default_backend())
    with open(os.path.join(OUTPUT_DIR, "crl.pem"), "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    return crl

# SSL/TLS Server
class CertificateRequestHandler(BaseHTTPRequestHandler):
    ca_key = None
    ca_cert = None
    
    def do_POST(self):
        print(f"Received POST request from {self.client_address}")
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        print(f"POST data: {post_data}")
        user_name, user_email = post_data.split(',')
        
        try:
            cert, _ = issue_user_certificate(self.ca_key, self.ca_cert, user_name, user_email)
            self.send_response(200)
            self.send_header('Content-type', 'application/x-pem-file')
            self.end_headers()
            self.wfile.write(cert.public_bytes(serialization.Encoding.PEM))
            print("Certificate issued successfully")
        except Exception as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(str(e).encode())
            print(f"Error issuing certificate: {e}")

def run_ssl_server(ca_key, ca_cert):
    server_address = ('127.0.0.1', 8443)
    httpd = HTTPServer(server_address, CertificateRequestHandler)
    CertificateRequestHandler.ca_key = ca_key
    CertificateRequestHandler.ca_cert = ca_cert
    
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=os.path.join(OUTPUT_DIR, "ca_cert.pem"),
            keyfile=os.path.join(OUTPUT_DIR, "ca_key.pem")
        )
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print("Starting SSL server on https://127.0.0.1:8443")
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    except Exception as e:
        print(f"Failed to start SSL server: {e}")
        raise


def validate_certificate(cert, ca_cert, crl):
    now = datetime.datetime.now(UTC)
    if cert.not_valid_before_utc > now or cert.not_valid_after_utc < now:
        return False, "Certificate is not within validity period"
    
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_parameters,
            cert.signature_hash_algorithm
        )
    except Exception:
        return False, "Signature verification failed"
    
    for revoked in crl:
        if cert.serial_number == revoked.serial_number:
            return False, "Certificate is revoked"
    
    return True, "Certificate is valid"


def verify_website_certificate(hostname, ca_cert, crl):
    try:
        # Load the certificate from file
        cert_path = os.path.join(OUTPUT_DIR, f"{hostname}_cert.pem")
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = load_pem_x509_certificate(cert_data, default_backend())
        
        # Validate the certificate
        valid, message = validate_certificate(cert, ca_cert, crl)
        return valid, message, cert
    except FileNotFoundError:
        return False, f"Certificate file {cert_path} not found", None
    except Exception as e:
        return False, f"Verification failed: {str(e)}", None
        


# Main execution
if __name__ == "__main__":
    # Create CA
    ca_key, ca_cert = create_ca()
    
    # Issue user certificates
    user_cert, user_key = issue_user_certificate(ca_key, ca_cert, "john_doe", "john@example.com")
    non_revoked_cert, _ = issue_user_certificate(ca_key, ca_cert, "jane_doe", "jane@example.com")
    
    # Create CRL with a revoked certificate
    crl = create_crl(ca_key, ca_cert, [user_cert.serial_number])
    
    # Start SSL server
    run_ssl_server(ca_key, ca_cert)
    
    # Save SSL certificate
    save_certificate(ca_cert, "ssl_cert.cert")
    
    # Analyze SSL certificate contents
    print("SSL Certificate Contents:")
    print(f"Subject: {ca_cert.subject}")
    print(f"Issuer: {ca_cert.issuer}")
    print(f"Serial Number: {ca_cert.serial_number}")
    print(f"Not Before: {ca_cert.not_valid_before_utc}")
    print(f"Not After: {ca_cert.not_valid_after_utc}")
    
    # Verify user certificates
    print("\nRevoked User Certificate Verification (john_doe):")
    valid, message = validate_certificate(user_cert, ca_cert, crl)
    print(f"Valid: {valid}")
    print(f"Message: {message}")
    
    print("\nNon-Revoked User Certificate Verification (jane_doe):")
    valid, message = validate_certificate(non_revoked_cert, ca_cert, crl)
    print(f"Valid: {valid}")
    print(f"Message: {message}")
    
    # Keep the script running
    print("Server running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down server...")

    # Optional: To verify kaggle.com (requires system CA store)
    hostname = "kaggle.com"
    issue_website_certificate(ca_key,ca_cert,hostname)
    valid, message, site_cert = verify_website_certificate(hostname, ca_cert, crl)
    
    print(f"\nWebsite Certificate Verification for {hostname}:")
    print(f"Valid: {valid}")
    print(f"Message: {message}")