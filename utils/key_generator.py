from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

with open('../keys/primary.pem', 'w') as f: # Change to secondary.pem for secondary
    f.write(pem.decode('utf-8'))

public_key = private_key.public_key()

pemp = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('../zones/public_keys/primary.pem', 'w') as f: # Change to secondary.pem for secondary
    f.write(pemp.decode('utf-8'))