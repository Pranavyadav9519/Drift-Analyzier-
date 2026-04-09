import time
import random
import requests

API_URL = "http://localhost:5050/check-url"

phishing_urls = [
    "http://update-paypal-security-account.com/login",
    "http://netflix-billing-update-now.net",
    "http://amazon-sec.com",
    "http://appleid-support-team.com",
    "http://chase-bank-verify-account.info",
    "http://free-iphone-winner-click-here.biz",
    "http://192.168.1.100/login.php",
    "http://instagram-verified-badge.com"
]

safe_urls = [
    "https://google.com",
    "https://github.com",
    "https://wikipedia.org",
    "https://youtube.com",
    "https://reddit.com",
    "https://linkedin.com",
    "https://twitter.com",
    "https://microsoft.com"
]

def simulate():
    print("🚀 Starting realistic traffic simulation against Sentinel Zero API...")
    while True:
        is_phishing = random.random() < 0.25 
        
        target_url = random.choice(phishing_urls) if is_phishing else random.choice(safe_urls)
        
        try:
            start = time.perf_counter()
            response = requests.post(
                API_URL, 
                json={"url": target_url},
                timeout=5
            )
            elapsed = int((time.perf_counter() - start) * 1000)
            
            if response.status_code == 200:
                data = response.json()
                verdict = data.get("verdict", "UNKNOWN")
                print(f"[{elapsed}ms] {target_url} -> {verdict}")
            else:
                print(f"Failed to check URL: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"Connection error: {e}")
            
        time.sleep(random.uniform(0.1, 2.0))

if __name__ == "__main__":
    time.sleep(2)
    simulate()
