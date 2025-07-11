import requests
import threading

class DirectoryEnumeration:
    def __init__(self, target_domain, wordlist, progress_dict):
        self.target_domain = target_domain
        self.wordlist = wordlist
        self.discovered_directories = []
        self.session = requests.Session()
        self.lock = threading.Lock()
        self.progress_dict = progress_dict
        self.total = len(wordlist)
        self.completed = 0

    def check_directory(self, directory):
        urls = [
            f'https://{self.target_domain}/{directory}',
            f'http://{self.target_domain}/{directory}'
        ]

        for url in urls:
            try:
                response = self.session.get(url, timeout=3)
                if response.status_code < 400:
                    with self.lock:
                        self.discovered_directories.append(url)
                    break
            except requests.RequestException:
                pass

        with self.lock:
            self.completed += 1
            self.progress_dict['progress'] = int((self.completed / self.total) * 100)

    def enumerate_directories(self):
        threads = []

        for directory in self.wordlist:
            thread = threading.Thread(target=self.check_directory, args=(directory,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        return self.discovered_directories
