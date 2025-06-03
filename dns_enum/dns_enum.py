import requests
import argparse

parser = argparse.ArgumentParser(prog = "dns_enum")
parser.add_argument('-w', '--wordlist', help = 'the file to use for %(prog)')
parser.add_argument('-u', '--hostname', help = 'the cible to attack')
args = parser.parse_args()

with open(args.wordlist, "r") as f:
  for word in f.readlines():
    url = f"https://{word.strip()}.{args.hostname}"
    try:
        r = requests.get(url)
    except Exception:
       pass
    else:
        print(f"[+] we got one! {url}")
 