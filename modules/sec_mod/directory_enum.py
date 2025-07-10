

class DirectoryEnumeration:
    def __init__(self, url, wordlist):
        self.url = url
        self.wordlist = wordlist        

    def enumerate_subdomain(self):
        print(self.wordlist)

