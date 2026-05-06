import re
import base64

env_file = '/Users/benyoung/projects/neosofia/cdp/.authentication.env'
with open(env_file, 'r') as f:
    text = f.read()

def fix_padding(m):
    key = m.group(1).strip()
    return "JWT_PRIVATE_KEY_PEM=" + key + '=' * ((4 - len(key) % 4) % 4)

text = re.sub(r'(?m)^JWT_PRIVATE_KEY_PEM=(.*)$', fix_padding, text)

def fix_padding_pub(m):
    key = m.group(1).strip()
    return "JWT_PUBLIC_KEY_PEM=" + key + '=' * ((4 - len(key) % 4) % 4)

text = re.sub(r'(?m)^JWT_PUBLIC_KEY_PEM=(.*)$', fix_padding_pub, text)

with open(env_file, 'w') as f:
    f.write(text)
print("Padding fixed.")
