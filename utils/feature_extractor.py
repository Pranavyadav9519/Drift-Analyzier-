import re
import urllib.parse
import tldextract
import requests
import math

class URLFeatureExtractor:
    def __init__(self, url):
        self.url = url
        self.features = {}

    def extract_features(self):
        self.features['length'] = self.get_length()
        self.features['num_special_chars'] = self.get_special_char_count()
        self.features['contains_ip'] = self.contains_ip()
        self.features['https_status'] = self.get_https_status()
        self.features['suspicious_tld'] = self.check_suspicious_tld()
        self.features['entropy'] = self.calculate_entropy()
        return self.features

    def get_length(self):
        return len(self.url)

    def get_special_char_count(self):
        return len(re.findall(r'[!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~]', self.url))

    def contains_ip(self):
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, self.url))

    def get_https_status(self):
        try:
            response = requests.get(self.url)
            return response.url.startswith('https://')
        except:
            return False

    def check_suspicious_tld(self):
        suspicious_tlds = ['.xyz', '.top', '.club', '.biz', '.info']
        extracted_tld = tldextract.extract(self.url).suffix
        return extracted_tld in suspicious_tlds

    def calculate_entropy(self):
        if not self.url:
            return 0
        # Calculate the entropy of the URL
        probabilities = [self.url.count(c) / len(self.url) for c in set(self.url)]
        entropy = -sum(p * math.log2(p) for p in probabilities)
        return entropy
