import re
import base64

env_file = '/Users/benyoung/projects/neosofia/cdp/.authentication.env'
with open(env_file, 'r') as f:
    text = f.read()

# pydantic in python strictly checks base64 encoded length without whitespace
# The length of 2272%4 is 0 so it's a multiple of 4, but padding might have been lost in replace

def regenerate_clean():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    pub_pem = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    # base64 standard correctly handles python's strict check
    priv_b64 = base64.b64encode(priv_pem).decode('utf-8')
    pub_b64 = base64.b64encode(pub_pem).decode('utf-8')
    return priv_b64, pub_b64

priv_b64, pub_b64 = regenerate_clean()

text = re.sub(r'(?m)^JWT_PRIVATE_KEY_PEM=.*$', f'JWT_PRIVATE_KEY_PEM={priv_b64}', text)
text = re.sub(r'(?m)^JWT_PUBLIC_KEY_PEM=.*$', f'JWT_PUBLIC_KEY_PEM={pub_b64}', text)

with open(env_file, 'w') as f:
    f.write(text)

