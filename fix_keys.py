import base64, re, os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
pub_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

priv_b64 = base64.urlsafe_b64encode(priv_pem).decode('utf-8').rstrip('=') + '=' * ((4 - len(base64.urlsafe_b64encode(priv_pem)) % 4) % 4)
pub_b64 = base64.urlsafe_b64encode(pub_pem).decode('utf-8').rstrip('=') + '=' * ((4 - len(base64.urlsafe_b64encode(pub_pem)) % 4) % 4)

# Wait, `pydantic` standard `base64` validator might expect standard b64. Let's use strict standard base64 if it complained about padding or use strict padding.
priv_b64 = base64.b64encode(priv_pem).decode('utf-8')
pub_b64 = base64.b64encode(pub_pem).decode('utf-8')

env_file = '/Users/benyoung/projects/neosofia/cdp/.authentication.env'
with open(env_file, 'r') as f:
    content = f.read()

content = re.sub(r'(?m)^JWT_PRIVATE_KEY_PEM=.*$', f'JWT_PRIVATE_KEY_PEM={priv_b64}', content)
content = re.sub(r'(?m)^JWT_PUBLIC_KEY_PEM=.*$', f'JWT_PUBLIC_KEY_PEM={pub_b64}', content)

with open(env_file, 'w') as f:
    f.write(content)
print("Keys updated.")
