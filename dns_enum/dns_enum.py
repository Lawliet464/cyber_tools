import argparse
import socket
import pyfiglet
from concurrent.futures import ThreadPoolExecutor 

def resolve_domain(word,domain):

  subdomain = f"{word.strip()}.{domain}"
  try:
        ip = socket.gethostbyname(subdomain)
        print(f"[+] we got one! {subdomain}-->{ip}")
        return subdomain, ip
  except (socket.gaierror, UnicodeError) as e:
        return None, None

def main():

 count = 0
 print(pyfiglet.figlet_format("DNS ENUMERATOR"))
 parser = argparse.ArgumentParser(prog = "dns_enum")
 parser.add_argument('-w', '--wordlist', help ='the file to use for %(prog)', required=True)
 parser.add_argument('-u', '--hostname', help ='the cible to attack', required=True)
 parser.add_argument('-o', '--output', default = 'output.txt', help='The text to save positive results')
 args = parser.parse_args()
  
 with open(args.wordlist, "r") as f: 
    words = [line.strip() for line in f if line.strip()]

 with open(args.output, "w") as out, ThreadPoolExecutor(max_workers=10) as executor:
      futures = executor.map(lambda word: resolve_domain(word, args.hostname), words)
      for subdomain, ip in futures:
           if ip:
               out.write(f"{subdomain}---->{ip}\n")
               count += 1
 if count:
    print(f"[+] Nous avons touvé {count} domaines good Luck, look at {args.output} to see them!!!!")
 else:
  print(f"[-] sorry we got none!!!")

if __name__ == "__main__" :
    main()    
   