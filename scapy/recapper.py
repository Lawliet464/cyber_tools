from scapy.all import TCP, rdpcap
import collections
import os
import re
import sys
import zlib

# Répertoire où on sauvegardera les images extraites
OUTDIR = '/root/Desktop/pictures'

# Répertoire contenant le fichier PCAP
PCAPS = '/root/Downloads'

# Structure pour stocker un en-tête + payload complet
Response = collections.namedtuple('Response', ['header', 'payload'])


def get_header(payload):
    try:
        # On prend tout jusqu'à la fin de l'en-tête HTTP (double CRLF)
        header_raw = payload[:payload.index(b'\r\n\r\n') + 2]
    except ValueError:
        sys.stdout.write('-')
        sys.stdout.flush()
        return None

    # On transforme en dictionnaire { "Content-Type": "...", ... }
    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', header_raw.decode(errors="ignore")))
    if 'Content-Type' not in header:
        return None
    return header


def extract_content(response, content_name='image'):
    content, content_type = None, None

    # On regarde si le type MIME contient "image"
    if content_name in response.header['Content-Type']:
        content_type = response.header['Content-Type'].split('/')[1]
        # On prend tout après l'en-tête HTTP
        content = response.payload[response.payload.index(b'\r\n\r\n') + 4:]

        # Si le contenu est compressé → on décompresse
        if 'Content-Encoding' in response.header:
            if response.header['Content-Encoding'] == "gzip":
                content = zlib.decompress(response.payload, zlib.MAX_WBITS | 32)
            elif response.header['Content-Encoding'] == "deflate":
                content = zlib.decompress(response.payload)

    return content, content_type


class Recapper:
    def __init__(self, fname):
        pcap = rdpcap(fname)
        self.sessions = pcap.sessions()  # clé = 5-tuple, valeur = liste de paquets
        self.responses = list()

    def get_responses(self):
        for session in self.sessions:
            payload = b''
            for packet in self.sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        payload += bytes(packet[TCP].payload)
                except IndexError:
                    sys.stdout.write('x')
                    sys.stdout.flush()

            if payload:
                header = get_header(payload)
                if header is None:
                    continue
                self.responses.append(Response(header=header, payload=payload))

    def write(self, content_name):
        for i, response in enumerate(self.responses):
            content, content_type = extract_content(response, content_name)
            if content and content_type:
                fname = os.path.join(OUTDIR, f'ex_{i}.{content_type}')
                print(f'Writing {fname}')
                with open(fname, 'wb') as f:
                    f.write(content)


if __name__ == '__main__':
    pfile = os.path.join(PCAPS, 'pcap.pcap')
    recapper = Recapper(pfile)
    recapper.get_responses()
    recapper.write('image')
