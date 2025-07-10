import dns.resolver
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

records_type = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SOA']
target_domain = input(Fore.CYAN + '[+] Enter Target Domain\n[*] Target Domain > ' + Style.RESET_ALL)

resolver = dns.resolver.Resolver()

for record in records_type:
    try:
        response = resolver.resolve(target_domain, record)
        print(f'\n{Fore.GREEN}[*] {record} records for {target_domain}')
        for data in response:
            print(f'  {Fore.WHITE}{data}')

    except dns.resolver.NoAnswer:
        print(f'\n{Fore.YELLOW}[!] No {record} record found for {target_domain}')
    except dns.resolver.NXDOMAIN:
        print(f'\n{Fore.RED}[!] Domain {target_domain} does not exist.')
        break
    except dns.resolver.NoNameservers:
        print(f'\n{Fore.RED}[!] No name servers available for {target_domain}')
        break
    except Exception as e:
        print(f'\n{Fore.MAGENTA}[!] Error resolving {record} for {target_domain}: {e}')
