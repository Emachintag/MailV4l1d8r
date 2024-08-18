import subprocess
import sys
import requests
import re
import socket
import ssl
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from termcolor import colored
from datetime import datetime, timedelta
import whois
from tqdm import tqdm, trange
import time

# Eksik modülleri yüklemek için fonksiyon
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Gerekli modüller
required_modules = ['requests', 'termcolor', 'colorama', 'whois', 'tqdm']

# Modülleri kontrol et ve eksik olanları yükle
for module in required_modules:
    try:
        __import__(module)
    except ImportError:
        print(f"{module} yüklenmedi, yükleniyor...")
        install(module)

# Tool banner
def main():
    banner = """\033[1m\033[96m
  __  __       _ _   __     ___  _  _ ____     ____  _  _      
 |  \\/  | ___ | | |  \\ \\   / / || || | __ )   | __ )| || | ___ 
 | |\\/| |/ _ \\| | |   \\ \\ / /| || || |  _ \\   |  _ \\| || |/ _ \\
 | |  | | (_) | | |    \\ V / |__   _| |_) |  | |_) |__   _  __/
 |_|  |_|\\___/|_|_|     \\_/     |_| |____/   |____/   |_| \\___|

                                        \t\t\t\033[96mby emachintag\033[0m
    \033[0m"""
    print(banner)

    email = input("Enter the email address: ")
    api_results = check_disposable_email(email)
    extra_results = additional_checks(email)
    print_results(email, api_results, extra_results)

# Yasaklı subdomain ve kelimeler
KEYWORDS = ["intel", "hunting", "dark web"]
FORBIDDEN_SUBDOMAINS = [".stu.", ".alumni.", ".alumna."]
FORBIDDEN_WORDS = ["student", "free"]

# Mevcut disposable email tespit fonksiyonu
def check_disposable_email(email):
    api_urls = [
        f"https://open.kickbox.com/v1/disposable/{email}",
        f"https://api.mailcheck.ai/email/{email}",
        f"https://isitarealemail.com/api/email/validate?email={email}",
        f"https://checkmail.disify.com/api/email/{email}",
        f"https://www.validator.pizza/email/{email}",
    ]
    
    results = {}
    with tqdm(total=len(api_urls), desc="Checking disposable email", ncols=100, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} {elapsed}') as pbar:
        for url in api_urls:
            time.sleep(0.5)  # Simülasyon için küçük bir gecikme
            try:
                response = requests.get(url)
                data = response.json()
                if "disposable" in data:
                    results[url] = data['disposable']
                elif "valid" in data:
                    results[url] = not data['valid']
                elif "status" in data:
                    results[url] = data["status"] == "invalid"
                elif "deliverable" in data:
                    results[url] = not data['deliverable']
                else:
                    results[url] = "unknown"
            except Exception as e:
                results[url] = f"Error: {str(e)}"
            pbar.update(1)
    
    return results

# Ek kontrolleri içeren fonksiyon
def additional_checks(email):
    results = []
    local_part, domain = email.split('@')

    # E-posta formatı ve sayısal yoğunluk kontrolü
    valid_format = re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None
    numeric_heavy = sum(c.isdigit() for c in local_part) > (len(local_part) / 2)
    results.append(("Email Format & Numeric Check", valid_format and not numeric_heavy, "Valid format and non-numeric local part"))

    # Yasaklı subdomain ve kelime kontrolü
    subdomain_check = all(subdomain not in domain for subdomain in FORBIDDEN_SUBDOMAINS)
    word_check = all(word not in domain for word in FORBIDDEN_WORDS)
    results.append(("Forbidden Subdomain Check", subdomain_check, "No forbidden subdomains"))
    results.append(("Forbidden Word Check", word_check, "No forbidden words"))

    # DNS kayıt kontrolü
    try:
        mx_records = socket.getaddrinfo(domain, None)
        results.append(("DNS Records Check", bool(mx_records), "DNS records found"))
    except Exception:
        results.append(("DNS Records Check", False, "No DNS records found"))

    # WHOIS domain yaşı kontrolü
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        is_old = creation_date and (datetime.now() - creation_date) >= timedelta(days=365)
        results.append(("Domain Age Check", is_old, "Domain is older than 1 year"))
    except Exception as e:
        # WHOIS sorgusu başarısız olursa hata vermeden devam edelim
        results.append(("Domain Age Check", False, f"WHOIS lookup failed: {str(e)}"))

    # SSL sertifikası kontrolü ve web içeriği analizi
    ssl_valid = False
    for url in [f"https://{domain}", f"https://www.{domain}"]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((urlparse(url).hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=urlparse(url).hostname) as ssock:
                    if ssock.cipher():
                        ssl_valid = True
                        results.append(("SSL Certificate Check", True, f"SSL certificate found for {url}"))
                        break
        except Exception:
            continue
    if not ssl_valid:
        results.append(("SSL Certificate Check", False, "No SSL certificate found"))

    return results

# Sonuçları renklendirilmiş şekilde yazdırma fonksiyonu
def print_results(email, api_results, extra_results):
    print(f"\n{colored('Checking email:', 'cyan')} {colored(email, 'yellow')}\n" + "="*50)
    disposable_count = 0
    not_disposable_count = 0
    
    print(colored("\n--- Disposable Email Check ---\n", "magenta", attrs=['bold']))
    for api, result in api_results.items():
        if result == "unknown":
            color = "yellow"
            status = "Unknown"
        elif result:
            color = "red"
            status = "Disposable"
            disposable_count += 1
        else:
            color = "green"
            status = "Not Disposable"
            not_disposable_count += 1
        
        print(colored(f"{api}: {status}", color))

    print(colored("\n--- Additional Checks ---\n", "magenta", attrs=['bold']))
    # Ek kontrollerin sonuçları
    for check_name, passed, message in extra_results:
        color = "green" if passed else "red"
        print(colored(f"{check_name}: {message}", color))
    
    print(colored("\n--- Final Result ---", "magenta", attrs=['bold']))
    if disposable_count > not_disposable_count:
        print(colored("Disposable", "red", attrs=['bold']))
    elif not_disposable_count > disposable_count:
        print(colored("Not Disposable", "green", attrs=['bold']))
    else:
        print(colored("Unknown", "yellow", attrs=['bold']))

if __name__ == "__main__":
    main()
