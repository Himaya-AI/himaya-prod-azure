#!/usr/bin/env python3
"""Write a VNC password file compatible with TigerVNC / RealVNC.
The VNC password format is DES-ECB encrypted with a fixed key where bits are reversed.
"""
import os, sys, stat

PASSWORD = os.environ.get("VNC_PASSWORD", "helios2024")[:8]
OUTFILE  = "/root/.vnc/passwd"

def reverse_bits(b):
    return int('{:08b}'.format(b)[::-1], 2)

pwd_bytes = PASSWORD.encode().ljust(8, b'\x00')[:8]
key_bytes = bytes(reverse_bits(k) for k in [23, 82, 107, 6, 35, 78, 88, 7])
pwd_rev   = bytes(reverse_bits(b) for b in pwd_bytes)

try:
    from Crypto.Cipher import DES
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "--break-system-packages", "pycryptodome"])
    from Crypto.Cipher import DES

cipher = DES.new(key_bytes, DES.MODE_ECB)
encrypted = cipher.encrypt(pwd_rev)

os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
with open(OUTFILE, "wb") as f:
    f.write(encrypted)
os.chmod(OUTFILE, stat.S_IRUSR | stat.S_IWUSR)
print(f"VNC password file written to {OUTFILE}")
