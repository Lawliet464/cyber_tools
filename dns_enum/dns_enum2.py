import argparse
import dns.resolver
import pyfiglet
from concurrent.futures import ThreadPoolExecutor
import socket
from datetime import datetime
import threading
from tqdm import tqdm
from colorama import init, Fore, Style
import random
import string
import csv
import json
import logging

# Init Colorama & Logger
init(autoreset=True)
lock = threading.Lock()

logging.basicConfig(
    filename='dns_enum.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def generate_fake_subdomain(domain):
    random_word = ''.join(random.choices(string.ascii_lowercase + string.digits, k=25))
    return f"{random_word}.{domain}"

def detect_wildcard(domain, dns_server=None):
    fake = generate_fake_subdomain(domain)
    try:
        if dns_server:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 3
            resolver.nameservers = [dns_server]
            resolver.resolve(fake, 'A')
        else:
            socket.gethostbyname(fake)
        print(f"[-] Wildcard DNS détecté : {fake} a retourné une adresse.")
        logging.warning(f"Wildcard DNS détecté : {fake}")
        return True
    except:
        return False

def detect_available_record_types(domain, dns_server=None):
    resolver = dns.resolver.Resolver()
    if dns_server:
        resolver.nameservers = [dns_server]
    resolver.timeout = 2
    resolver.lifetime = 3
    common_types = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT']
    available = []

    for rtype in common_types:
        try:
            resolver.resolve(domain, rtype)
            available.append(rtype)
        except:
            continue
    return available

def is_cloudflare_ip(ip):
    cloudflare_prefixes = [
        "104.", "172.64.", "162.159.", "198.41.", "188.114.", "190.93.",
        "197.234.", "141.101.", "103.21.", "103.22.", "103.31."
    ]
    return any(ip.startswith(prefix) for prefix in cloudflare_prefixes)

def call_args():
    print(Fore.CYAN + pyfiglet.figlet_format("DNS ENUMERATOR"))
    parser = argparse.ArgumentParser(prog="dns_enum")
    parser.add_argument('-w', '--wordlist', required=True)
    parser.add_argument('-u', '--hostname', required=True)
    parser.add_argument('-o', '--output', default='output.txt')
    parser.add_argument('-th', '--threads', type=int, default=15)
    parser.add_argument('-S', '--server_dns')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-r', '--record', default='A')
    parser.add_argument('--format', choices=['txt', 'csv', 'json'], default='txt')
    parser.add_argument('--auto-records', action='store_true')
    parser.add_argument('--dry-run', action='store_true',
                        help="Affiche les sous-domaines qui seraient testés sans effectuer de requêtes DNS")
    parser.add_argument('--bypass-cloudflare', action='store_true',
                        help="Ignore les IPs Cloudflare pour ne garder que les sous-domaines exposant une IP réelle.")
    parser.add_argument('--scan-ports', action='store_true', help="Scanne les ports courants sur les IPs résolues")

    return parser.parse_args()

def resolve_with_server(word, domain, dns_server, record_types, verbose=False, max_retries=3):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    resolver.nameservers = [dns_server]
    subdomain = f"{word.strip()}.{domain}"
    results = []

    for record_type in record_types:
        attempt = 0
        while attempt < max_retries:
            try:
                answers = resolver.resolve(subdomain, record_type)
                for rdata in answers:
                    results.append((record_type, subdomain, rdata.to_text(), "OK"))
                break
            except dns.resolver.NXDOMAIN:
                if verbose:
                    results.append((record_type, subdomain, "NXDOMAIN", "FAIL"))
                break
            except dns.resolver.NoAnswer:
                if verbose:
                    results.append((record_type, subdomain, "NoAnswer", "FAIL"))
                break
            except (dns.resolver.Timeout, dns.exception.DNSException):
                attempt += 1
                if attempt >= max_retries and verbose:
                    results.append((record_type, subdomain, "Timeout or DNS error", "FAIL"))
    return results

def resolve_without_server(word, domain, verbose=False):
    subdomain = f"{word.strip()}.{domain}"
    try:
        ip = socket.gethostbyname(subdomain)
        return [('A', subdomain, ip, "OK")]
    except (socket.gaierror, UnicodeError):
        if verbose:
            return [('A', subdomain, "Unresolved", "FAIL")]
        else:
            return []

def scan_ports(ip, ports=[21, 22, 23, 53, 80, 110, 139, 143, 443, 445, 8080], timeout=1):
    open_ports = []

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except:
            return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_port, ports))

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports

def is_takeover_possible(cname_target):
    import requests
    takeover_signatures = {
        "github.io": "There isn't a GitHub Pages site here",
        "gitlab.io": "The page you are looking for could not be found",
        "herokuapp.com": "No such app",
        "amazonaws.com": "NoSuchBucket",
        "bitbucket.io": "Repository not found",
        "cloudfront.net": "ERROR: The request could not be satisfied"
    }
    try:
        response = requests.get(f"http://{cname_target}", timeout=3)
        body = response.text
        for service, signature in takeover_signatures.items():
            if service in cname_target and signature.lower() in body.lower():
                return True, service
    except requests.RequestException:
        pass
    return False, None


def export_results(results_list, output_file, format_type):
    if format_type == "txt":
        with open(output_file, 'w') as f:
            for record_type, sub, val, status in results_list:
                line = f"[{record_type}] {sub} ----> {val} [{status}]\n"
                f.write(line)

    elif format_type == "csv":
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Type", "Subdomain", "Value", "Status"])
            for record_type, sub, val, status in results_list:
                writer.writerow([record_type, sub, val, status])

    elif format_type == "json":
        data = [{"type": r, "subdomain": s, "value": v, "status": st} for r, s, v, st in results_list]
        with open(output_file, 'w') as jsonfile:
            json.dump(data, jsonfile, indent=2)

def is_behind_cloudflare(domain):
    cf_ns_keywords = ["cloudflare"]
    cf_ip_prefixes = ["104.", "172.64.", "162.159.", "198.41."]

    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for r in ns_records:
            if any(kw in r.to_text().lower() for kw in cf_ns_keywords):
                logging.info(f"Cloudflare détecté via NS : {r.to_text()}")
                return True

        a_records = dns.resolver.resolve(domain, 'A')
        for r in a_records:
            ip = r.to_text()
            if any(ip.startswith(prefix) for prefix in cf_ip_prefixes):
                logging.info(f"Cloudflare détecté via IP : {ip}")
                return True

    except Exception as e:
        logging.warning(f"Erreur lors de la détection Cloudflare : {e}")
        return False

    return False

def main(args):
    start_time = datetime.now()
    logging.info("Démarrage de l'énumération")

    try:
        with open(args.wordlist, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}[!] Erreur d'ouverture du fichier wordlist: {e}")
        logging.error(f"Erreur ouverture wordlist: {e}")
        return

    if args.dry_run:
        print(Fore.CYAN + "[*] Mode dry-run activé. Affichage des sous-domaines à tester :\n")
        for word in words:
            sub = f"{word.strip()}.{args.hostname}"
            print(f" - {sub}")
        print(Fore.YELLOW + f"\n[*] Total : {len(words)} sous-domaines générés. Aucune requête DNS n’a été effectuée.")
        return

    if is_behind_cloudflare(args.hostname):
        print(Fore.YELLOW + f"[!] ⚠ Le domaine {args.hostname} semble être protégé par Cloudflare.")
        logging.info(f"{args.hostname} semble être protégé par Cloudflare.")

    total = len(words)
    if args.auto_records:
        print(Fore.CYAN + "[*] Détection automatique des types de records disponibles...")
        record_types = detect_available_record_types(args.hostname, args.server_dns)
        if not record_types:
            print(Fore.RED + "[!] Aucun type de record détecté sur le domaine.")
            logging.warning("Aucun record type détecté")
            return
        else:
            print(Fore.GREEN + f"[+] Types détectés : {', '.join(record_types)}")
            logging.info(f"Types détectés : {', '.join(record_types)}")
    else:
        record_types = [r.strip().upper() for r in args.record.split(',') if r.strip()]

    results_list = []
    wildcard = detect_wildcard(args.hostname, args.server_dns)
    if wildcard:
        answer = input("Continuer quand même ? (y/n): ")
        if answer.lower() != 'y':
            print(f"{Fore.RED}Sortie...")
            logging.info("Abandon suite wildcard")
            return

    print(f"{Fore.YELLOW}[+] Démarrage de l'énumération sur {total} mots...")

    def worker(word):
        if args.server_dns:
            return resolve_with_server(word, args.hostname, args.server_dns, record_types, args.verbose)
        else:
            if record_types != ['A']:
                return []
            return resolve_without_server(word, args.hostname, args.verbose)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        with tqdm(total=total, desc="Progression", unit="subdomain") as progress:
            futures = executor.map(worker, words)
            for result_group in futures:
                with lock:
                    results_list.extend(result_group)
                    progress.update(1)

    found = 0
    for record_type, subdomain, value, status in results_list:
        if status == "OK":
            if record_type == "CNAME" and args.verbose:
               takeover, service = is_takeover_possible(value)
               if takeover:
                   print(f"{Fore.RED}[!] Takeover potentiel sur {subdomain} (service: {service})")
                   logging.warning(f"Takeover potentiel sur {subdomain} (via {service})")

            if args.bypass_cloudflare and record_type == "A" and is_cloudflare_ip(value):
                continue
            print(f"{Fore.GREEN}[{record_type}] {subdomain} ----> {value}")
            logging.info(f"[{record_type}] {subdomain} ----> {value} [OK]")
            found += 1
        if args.scan_ports and record_type == 'A':
           try:
              open_ports = scan_ports(value)
              if open_ports:
                 ports_str = ', '.join(map(str, open_ports))
                 print(f"{Fore.MAGENTA}  ↳ Ports ouverts sur {value} : {ports_str}")
                 logging.info(f"Ports ouverts sur {value} : {ports_str}")
           except Exception as e:
              logging.warning(f"Erreur scan ports {value}: {e}")

        elif args.verbose:
            print(f"{Fore.RED}[{record_type}] {subdomain} ----> {value}")
            logging.warning(f"[{record_type}] {subdomain} ----> {value} [FAIL]")

    export_results(results_list, args.output, args.format)
    duration = datetime.now() - start_time

    print(f"\n{Fore.CYAN}{'\u2714 Terminé !':^60}")
    print(f"{Fore.GREEN}{'+ ' + str(found) + ' enregistrements trouvés.':^60}")
    print(f"{Fore.YELLOW}{'\u23f1 Temps d\'exécution : ' + str(duration):^60}")
    logging.info("%d enregistrements trouvés", found)
    logging.info("Temps d'exécution : %s", str(duration))
    logging.info("Export terminé : %s (%s)", args.output, args.format)

if __name__ == "__main__":
    args = call_args()
    main(args)

