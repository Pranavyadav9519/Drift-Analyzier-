import re
import math
import urllib.parse
import tldextract

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'netflix.com', 'wikipedia.org', 'stackoverflow.com', 'reddit.com', 'github.io',
}

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'biz', 'info', 'tk', 'ml', 'ga', 'cf', 'gq',
    'pw', 'cc', 'su', 'nu', 'ws', 'icu', 'online', 'site', 'tech',
}

PHISHING_KEYWORDS = [
    'login', 'signin', 'account', 'verify', 'update', 'secure', 'banking',
    'password', 'confirm', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
    'support', 'service', 'alert', 'suspended', 'unusual', 'activity',
]


class URLFeatureExtractor:
    def __init__(self, url: str):
        self.url = url
        self.parsed = urllib.parse.urlparse(url)
        self.extracted = tldextract.extract(url)
        self.features: dict = {}

    def extract_features(self) -> dict:
        self.features['url_length'] = self.get_length()
        self.features['num_dots'] = self.count_char('.')
        self.features['num_hyphens'] = self.count_char('-')
        self.features['num_underscores'] = self.count_char('_')
        self.features['num_slashes'] = self.count_char('/')
        self.features['num_question_marks'] = self.count_char('?')
        self.features['num_at_signs'] = self.count_char('@')
        self.features['num_ampersands'] = self.count_char('&')
        self.features['num_equals'] = self.count_char('=')
        self.features['num_special_chars'] = self.get_special_char_count()
        self.features['contains_ip'] = int(self.contains_ip())
        self.features['has_https'] = int(self.has_https())
        self.features['suspicious_tld'] = int(self.check_suspicious_tld())
        self.features['is_trusted_domain'] = int(self.is_trusted_domain())
        self.features['subdomain_count'] = self.count_subdomains()
        self.features['domain_length'] = len(self.extracted.domain)
        self.features['path_length'] = len(self.parsed.path)
        self.features['query_length'] = len(self.parsed.query)
        self.features['num_phishing_keywords'] = self.count_phishing_keywords()
        self.features['entropy'] = self.calculate_entropy()
        self.features['has_port'] = int(bool(self.parsed.port))
        self.features['double_slash_in_path'] = int('//' in self.parsed.path)
        return self.features

    def get_length(self) -> int:
        return len(self.url)

    def count_char(self, char: str) -> int:
        return self.url.count(char)

    def get_special_char_count(self) -> int:
        return len(re.findall(r'[!"#$%&\'()*+,\-./:;<=>?@\[\\\]^_`{|}~]', self.url))

    def contains_ip(self) -> bool:
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return bool(re.search(ip_pattern, self.url))

    def has_https(self) -> bool:
        return self.parsed.scheme == 'https'

    def check_suspicious_tld(self) -> bool:
        return self.extracted.suffix in SUSPICIOUS_TLDS

    def is_trusted_domain(self) -> bool:
        domain = f"{self.extracted.domain}.{self.extracted.suffix}"
        return domain in TRUSTED_DOMAINS

    def count_subdomains(self) -> int:
        subdomain = self.extracted.subdomain
        if not subdomain:
            return 0
        return len(subdomain.split('.'))

    def count_phishing_keywords(self) -> int:
        url_lower = self.url.lower()
        return sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)

    def calculate_entropy(self) -> float:
        if not self.url:
            return 0.0
        probabilities = [self.url.count(c) / len(self.url) for c in set(self.url)]
        return -sum(p * math.log2(p) for p in probabilities)
