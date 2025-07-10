import requests
import threading

class SubdomainEnumeration:
    def __init__(self, target_domain, wordlist, progress_dict):
        self.target_domain = target_domain
        self.wordlist = wordlist
        self.discovered_subdomains = []
        self.session = requests.Session()
        self.lock = threading.Lock()
        self.progress_dict = progress_dict
        self.total = len(wordlist)
        self.completed = 0

    def check_subdomain(self, subdomain):
        urls = [
            f'https://{subdomain}.{self.target_domain}',
            f'http://{subdomain}.{self.target_domain}'
        ]

        for url in urls:
            try:
                response = self.session.get(url, timeout=3)
                if response.status_code < 400:
                    with self.lock:
                        self.discovered_subdomains.append(url)
                    break
            except requests.RequestException:
                pass

        with self.lock:
            self.completed += 1
            self.progress_dict['progress'] = int((self.completed / self.total) * 100)

    def enumerate_subdomain(self):
        threads = []

        for subdomain in self.wordlist:
            thread = threading.Thread(target=self.check_subdomain, args=(subdomain,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        return self.discovered_subdomains
