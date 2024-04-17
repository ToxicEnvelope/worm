import os
import sys
import time
import socket
import base64
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dataclasses import dataclass, field, asdict

os.chmod(sys.argv[0], 777)


@dataclass
class WormDigest:
    key: bytes = field(default=b"mysecretpassword")
    def __init__(self): self.cipher = AES.new(self.key, AES.MODE_ECB)

    def EncodeAES(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        return self.cipher.encrypt(
            pad(
                base64.urlsafe_b64encode(
                    plaintext
                ), AES.block_size
            )
        )

    def DecodeAES(self, ciphertext):
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode()
        return base64.urlsafe_b64decode(
            unpad(
                self.cipher.decrypt(
                    ciphertext
                ), AES.block_size
            )
        ).decode('utf-8')


@dataclass
class INET:
    public_ip: str = field(default=str)
    private_ip: str = field(default=str)
    bridges: list = field(default=list)
    last_refresh: float = field(init=False, default=float)
    def __repr__(self): return "<INET %r>" % asdict(self)
    def __init__(self): self.refresh()

    def refresh(self):
        self.private_ip = socket.gethostbyname(socket.gethostname())
        self.bridges = socket.gethostbyname_ex(socket.gethostname())[2]
        self.last_refresh = time.time()
        return self


@dataclass
class GeoIP:
    country: str = field(init=False)
    countryCode: str = field(init=False)
    region: str = field(init=False)
    regionName: str = field(init=False)
    city: str = field(init=False)
    zip: str = field(init=False)
    lat: float = field(init=False)
    lon: float = field(init=False)
    timezone: str = field(init=False)
    isp: str = field(init=False)
    AS: str = field(init=False)
    query: str = field(init=False)
    last_refresh: float = field(init=False, default=float)
    def __repr__(self): return "<GeoIP %r>" % asdict(self)
    def __init__(self): self.refresh()

    def refresh(self):
        data = requests.get('http://ip-api.com/json')
        for k, v in data.json().items():
            if k == 'as':
                self.AS = v
            else:
                setattr(self, k, v)
        self.last_refresh = time.time()
        return self


@dataclass
class Host:
    os_name: str = field(default=os.name)
    platform: str = field(default=sys.platform)
    id: str = field(init=False, default=str)
    last_refresh: float = field(init=False, default=float)
    geoip: GeoIP = field(default=GeoIP)
    inet: INET = field(default=INET)
    def __repr__(self): return "<Host %r>" % asdict(self)
    def __init__(self): self.id = hex(id(self))

    def refresh(self):
        self.geoip = GeoIP()
        self.inet = INET()
        self.inet.public_ip = self.geoip.query
        self.os_name = os.name
        self.platform = sys.platform
        self.last_refresh = time.time()
        return self


host = Host()
wd = WormDigest()
host.refresh()
enc_data = wd.EncodeAES(host.geoip.query)
print(enc_data)
time.sleep(3)
plaintext = wd.DecodeAES(enc_data)
print(plaintext)
