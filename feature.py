import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None
        self.features = []

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            self.response = None
            self.soup = None

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            self.domain = ""

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

        self.extract_features()

    def extract_features(self):
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Https())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    def longUrl(self):
        return 1 if len(self.url) < 54 else (0 if len(self.url) <= 75 else -1)

    def shortUrl(self):
        pattern = r'bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|snipurl\.com|'
        if re.search(pattern, self.url):
            return -1
        return 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind("//") > 6 else 1

    def prefixSuffix(self):
        return -1 if "-" in self.domain else 1

    def SubDomains(self):
        dot_count = len(re.findall(r"\.", self.url))
        return 1 if dot_count == 1 else (0 if dot_count == 2 else -1)

    def Https(self):
        return 1 if self.urlparse and self.urlparse.scheme == "https" else -1

    def DomainRegLen(self):
        try:
            exp = self.whois_response.expiration_date
            create = self.whois_response.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(create, list): create = create[0]
            age = (exp.year - create.year) * 12 + (exp.month - create.month)
            return 1 if age >= 12 else -1
        except:
            return -1

    def Favicon(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if self.url in link['href'] or self.domain in link['href'] or len(re.findall(r"\.", link['href'])) == 1:
                    return 1
            return -1
        except:
            return -1

    def NonStdPort(self):
        return -1 if ":" in self.domain else 1

    def HTTPSDomainURL(self):
        return -1 if "https" in self.domain else 1

    def RequestURL(self):
        try:
            total, success = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for item in self.soup.find_all(tag, src=True):
                    src = item['src']
                    if self.url in src or self.domain in src or len(re.findall(r"\.", src)) == 1:
                        success += 1
                    total += 1
            percentage = success / total * 100 if total else 0
            return 1 if percentage < 22 else (0 if percentage < 61 else -1)
        except:
            return -1

    def AnchorURL(self):
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                href = a['href'].lower()
                if "#" in href or "javascript" in href or "mailto" in href or not (self.url in href or self.domain in href):
                    unsafe += 1
                total += 1
            percentage = unsafe / total * 100 if total else 0
            return 1 if percentage < 31 else (0 if percentage < 67 else -1)
        except:
            return -1

    def LinksInScriptTags(self):
        try:
            total, success = 0, 0
            for tag in ['link', 'script']:
                for item in self.soup.find_all(tag, href=True if tag == 'link' else 'src'):
                    val = item['href'] if tag == 'link' else item['src']
                    if self.url in val or self.domain in val or len(re.findall(r"\.", val)) == 1:
                        success += 1
                    total += 1
            percentage = success / total * 100 if total else 0
            return 1 if percentage < 17 else (0 if percentage < 81 else -1)
        except:
            return -1

    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            for form in forms:
                action = form['action']
                if action in ["", "about:blank"]:
                    return -1
                elif self.url not in action and self.domain not in action:
                    return 0
            return 1
        except:
            return -1

    def InfoEmail(self):
        try:
            return -1 if re.findall(r"mailto:", str(self.soup)) else 1
        except:
            return -1

    def AbnormalURL(self):
        try:
            return 1 if self.response and self.whois_response and self.response.text == str(self.whois_response) else -1
        except:
            return -1

    def WebsiteForwarding(self):
        try:
            n = len(self.response.history)
            return 1 if n <= 1 else (0 if n <= 4 else -1)
        except:
            return -1

    def StatusBarCust(self):
        try:
            return 1 if re.findall(r"<script>.+onmouseover.+</script>", self.response.text) else -1
        except:
            return -1

    def DisableRightClick(self):
        try:
            return 1 if re.findall(r"event.button ?== ?2", self.response.text) else -1
        except:
            return -1

    def UsingPopupWindow(self):
        try:
            return 1 if re.findall(r"alert\(", self.response.text) else -1
        except:
            return -1

    def IframeRedirection(self):
        try:
            return 1 if re.findall(r"<iframe>|<frameBorder>", self.response.text) else -1
        except:
            return -1

    def AgeofDomain(self):
        try:
            create = self.whois_response.creation_date
            if isinstance(create, list): create = create[0]
            age = (date.today().year - create.year) * 12 + (date.today().month - create.month)
            return 1 if age >= 6 else -1
        except:
            return -1

    def DNSRecording(self):
        return self.AgeofDomain()  # same logic

    def WebsiteTraffic(self):
        try:
            rank_data = urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read()
            rank = BeautifulSoup(rank_data, "xml").find("REACH")['RANK']
            return 1 if int(rank) < 100000 else 0
        except:
            return -1

    def PageRank(self):
        try:
            r = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            rank = int(re.findall(r"Global Rank: ([0-9]+)", r.text)[0])
            return 1 if rank > 0 and rank < 100000 else -1
        except:
            return -1

    def GoogleIndex(self):
        try:
            results = list(search(self.url, num_results=5))
            return 1 if results else -1
        except:
            return 1

    def LinksPointingToPage(self):
        try:
            count = len(re.findall(r"<a href=", self.response.text))
            return 1 if count == 0 else (0 if count <= 2 else -1)
        except:
            return -1

    def StatsReport(self):
        try:
            malicious_urls = r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly'
            malicious_ips = r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116'
            if re.search(malicious_urls, self.url) or re.search(malicious_ips, socket.gethostbyname(self.domain)):
                return -1
            return 1
        except:
            return 1

    def getFeaturesList(self):
        return self.features
