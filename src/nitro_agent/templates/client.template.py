import sys
import json
import time
import os
import base64
import cbor2
import traceback
import requests
import boto3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils

ROOT_CA_PEM = """{root_ca}"""

EXPECTED_PCRS = {pcr_bindings}

def verify_cert_signature(issuer_cert, subject_cert):
    """Dynamically verifies a certificate signature supporting both RSA and ECDSA."""
    public_key = issuer_cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                subject_cert.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                subject_cert.signature,
                subject_cert.tbs_certificate_bytes,
                ec.ECDSA(subject_cert.signature_hash_algorithm),
            )
        else:
            raise ValueError(f"Unsupported public key type: {type(public_key)}")
    except Exception as e:
        raise e

def verify_attestation(attestation_doc_b64, client_nonce):
    print("Decoding attestation document...", file=sys.stderr)
    doc_bytes = base64.b64decode(attestation_doc_b64)
    cose_sign1 = cbor2.loads(doc_bytes)
    payload_bytes = cose_sign1[2]
    doc = cbor2.loads(payload_bytes)

    print("Verifying nonce...", file=sys.stderr)
    received_nonce = doc.get('nonce')
    if received_nonce != client_nonce:
        print(f"FATAL: Nonce mismatch! Expected {client_nonce.hex()}, got {received_nonce.hex() if received_nonce else 'None'}", file=sys.stderr)
        sys.exit(1)

    print("Verifying PCRs...", file=sys.stderr)
    doc_pcrs = doc.get('pcrs', {})
    
    for pcr_key, expected_val in EXPECTED_PCRS.items():
        idx = int(pcr_key.replace("PCR", ""))
        received_val = doc_pcrs.get(idx, b'').hex()
        if received_val != expected_val:
            print(f"FATAL: PCR{idx} mismatch! Expected {expected_val}, got {received_val}", file=sys.stderr)
            sys.exit(1)

    print("Verifying Certificate Chain...", file=sys.stderr)
    cabundle = doc.get('cabundle', [])
    leaf_bytes = doc.get('certificate')
    
    if not leaf_bytes and cabundle:
        leaf_bytes = cabundle.pop(0)
    
    if not leaf_bytes:
        print("FATAL: Attestation document does not contain a leaf certificate.", file=sys.stderr)
        sys.exit(1)

    try:
        root_ca = x509.load_pem_x509_certificate(ROOT_CA_PEM.strip().encode('utf-8'), default_backend())
        
        certs = []
        leaf_cert = x509.load_der_x509_certificate(leaf_bytes, default_backend())
        certs.append(leaf_cert)

        for i, c_bytes in enumerate(reversed(cabundle)):
            cert = x509.load_der_x509_certificate(c_bytes, default_backend())
            certs.append(cert)

        for i in range(len(certs) - 1):
            subject = certs[i]
            issuer = certs[i+1]
            if subject.issuer != issuer.subject:
                print(f"WARNING: Subject issuer {subject.issuer} does not match Issuer subject {issuer.subject}!")

            verify_cert_signature(issuer, subject)
            
        last_cert = certs[-1]
        
        if last_cert.public_bytes(serialization.Encoding.PEM) == root_ca.public_bytes(serialization.Encoding.PEM):
             pass
        else:
             if last_cert.issuer != root_ca.subject:
                 print(f"WARNING: Last cert issuer {last_cert.issuer} does not match Root CA subject {root_ca.subject}")
                 
             verify_cert_signature(root_ca, last_cert)

        # Verify the COSE_Sign1 signature over the attestation payload
        print("Verifying COSE_Sign1 signature...", file=sys.stderr)
        protected_header = cose_sign1[0]
        signature = cose_sign1[3]
        sig_structure = cbor2.dumps([
            "Signature1",
            protected_header,
            b"",
            payload_bytes,
        ])

        leaf_pub_key = leaf_cert.public_key()
        if not isinstance(leaf_pub_key, ec.EllipticCurvePublicKey):
            raise ValueError(f"Leaf certificate has unexpected key type: {type(leaf_pub_key)}")

        # COSE signatures use IEEE P1363 format (r || s); cryptography expects DER
        coord_len = len(signature) // 2
        r = int.from_bytes(signature[:coord_len], 'big')
        s = int.from_bytes(signature[coord_len:], 'big')
        der_sig = utils.encode_dss_signature(r, s)
        leaf_pub_key.verify(der_sig, sig_structure, ec.ECDSA(hashes.SHA384()))

    except Exception as e:
        print(f"FATAL: Attestation verification failed: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)

    print("Attestation Verification Passed!", file=sys.stderr)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 client.py <host_ip> <kms_key_arn>", file=sys.stderr)
        sys.exit(1)
    
    host_ip = sys.argv[1]
    kms_key_arn = sys.argv[2]
    proxy_url = f"https://{host_ip}/enclave"
    
    # Disable warnings for self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # 1. Attestation Phase
    client_nonce = os.urandom(32)
    nonce_b64 = base64.b64encode(client_nonce).decode('utf-8')
    
    print(f"Connecting to enclave via proxy at {proxy_url} for attestation...", file=sys.stderr)
    try:
        req_payload = {"action": "get_attestation", "nonce": nonce_b64}
        resp = requests.post(proxy_url, json=req_payload, timeout=10, verify=False)
        resp.raise_for_status()
        
        resp_data = resp.json()
        if "error" in resp_data:
            print(f"Enclave returned error: {resp_data['error']}", file=sys.stderr)
            sys.exit(1)
            
        verify_attestation(resp_data["attestation_doc_b64"], client_nonce)
    except Exception as e:
        print(f"Failed to communicate with proxy for attestation: {e}", file=sys.stderr)
        sys.exit(1)
        
    # 2. Data Phase
    print("Loading data.json...", file=sys.stderr)
    try:
        with open('data.json', 'r') as f:
            data_str = f.read()
    except Exception as e:
        print(f"Failed to load data.json: {e}", file=sys.stderr)
        sys.exit(1)
        
    # Encrypt data locally using KMS before sending
    print("Encrypting data locally via AWS KMS...", file=sys.stderr)
    try:
        kms = boto3.client('kms')
        enc_resp = kms.encrypt(
            KeyId=kms_key_arn,
            Plaintext=data_str.encode('utf-8')
        )
        ciphertext_b64 = base64.b64encode(enc_resp['CiphertextBlob']).decode('utf-8')
    except Exception as e:
        print(f"Failed to encrypt data with KMS: {e}", file=sys.stderr)
        print("Make sure you have valid AWS credentials configured locally.", file=sys.stderr)
        sys.exit(1)
        
    # Send encrypted data to the enclave
    print("Connecting to enclave proxy to send encrypted data...", file=sys.stderr)
    try:
        req_payload = {"ciphertext_b64": ciphertext_b64}
        resp = requests.post(proxy_url, json=req_payload, timeout=150, verify=False)
        
        try:
            parsed = resp.json()
            print(json.dumps(parsed, indent=2))
        except:
            print(resp.text)
            
        if not resp.ok:
            sys.exit(1)
    except Exception as e:
        print(f"Failed to communicate with proxy for data: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()