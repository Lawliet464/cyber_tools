import argparse
import dns.resolver
import pyfiglet
from concurrent.futures import ThreadPoolExecutor
import socket

def call_args():
    print(pyfiglet.figlet_format("DNS ENUMERATOR"))
    parser = argparse.ArgumentParser(prog="dns_enum")
    parser.add_argument('-w', '--wordlist', required=True, help='File with subdomain words')
    parser.add_argument('-u', '--hostname', required=True, help='Target domain')
    parser.add_argument('-o', '--output', default='output.txt', help='File to save results')
    parser.add_argument('-th', '--threads', type=int, default=25, help='Max threads')
    parser.add_argument('-S', '--server_dns', help='DNS server to use')
    parser.add_argument('-r', '--record', default='A', help='Comma-separated DNS record types to test (e.g. A,MX,CNAME)')
    return parser.parse_args()

def resolve_with_server(word, domain, dns_server, record_types):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    resolver.nameservers = [dns_server]

    subdomain = f"{word.strip()}.{domain}"
    results = []

    for record_type in record_types:
        try:
            answers = resolver.resolve(subdomain, record_type)
            for rdata in answers:
                results.append((record_type, subdomain, rdata.to_text()))
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer, dns.exception.DNSException):
            continue
    return results

def resolve_without_server(word, domain):
    subdomain = f"{word.strip()}.{domain}"
    try:
        ip = socket.gethostbyname(subdomain)
        return [('A', subdomain, ip)]
    except (socket.gaierror, UnicodeError):
        return []

def main(args):
    try:
        with open(args.wordlist, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Erreur d'ouverture du fichier wordlist: {e}")
        return

    record_types = [r.strip().upper() for r in args.record.split(',') if r.strip()]
    found = 0

    with open(args.output, 'w') as out, ThreadPoolExecutor(max_workers=args.threads) as executor:
        if args.server_dns:
            futures = executor.map(lambda word: resolve_with_server(word, args.hostname, args.server_dns, record_types), words)
        else:
            # Pas de support multi-record sans DNS server => fallback à socket uniquement pour A
            if record_types != ['A']:
                print("[!] Sans serveur DNS, seul le record 'A' est supporté.")
                return
            futures = executor.map(lambda word: resolve_without_server(word, args.hostname), words)

        for results in futures:
            for record_type, subdomain, value in results:
                out.write(f"[{record_type}] {subdomain} ----> {value}\n")
                found += 1

    if found:
        print(f"[+] Trouvé {found} enregistrements ! Regarde {args.output}")
    else:
        print("[-] Aucun résultat détecté.")

if __name__ == "__main__":
    args = call_args()
    main(args)
