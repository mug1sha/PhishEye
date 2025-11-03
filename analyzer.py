import re
import tldextract
import math
import whois
import socket


# helper: entropy of string
def shannon_entropy(s: str) -> float:
# compute frequency
   if not s:
      return 0.0
   freq = {}
   for ch in s:
      freq[ch] = freq.get(ch, 0) + 1
   entropy = 0.0
   for v in freq.values():
      p = v / len(s)
   entropy -= p * math.log2(p)
   return entropy

def extract_features(url: str):
   
   # returns list of features suitable for the ML model
   u = url.strip()
   features = []


   # length
   features.append(len(u))


   # count digits
   features.append(sum(c.isdigit() for c in u))


   # count hyphens
   features.append(u.count('-'))


   # count query params
   features.append(u.count('?'))


   # entropy
   features.append(shannon_entropy(u))


   # subdomain count
   te = tldextract.extract(u)
   sub = te.subdomain
   sub_count = 0 if not sub else sub.count('.') + 1
   features.append(sub_count)


   # has ip address instead of domain
   ip_match = re.search(r'https?://(\d{1,3}\.){3}\d{1,3}', u)
   features.append(1 if ip_match else 0)


   # uses https
   features.append(1 if u.startswith('https://') else 0)


   return features


def analyze_url(url: str):
   """Lightweight rule-based checks. Returns (score_float_0_1, reasons_list)"""
   reasons = []
   score = 0.0
   u = url.strip()


   # basic invalid URL
   if not re.match(r'https?://', u):
      reasons.append('Missing scheme (add http:// or https://)')
      score += 0.2
      
   # domain checks
   te = tldextract.extract(u)
   domain = te.domain + '.' + te.suffix if te.suffix else te.domain


   # suspicious length
   if len(u) > 100:
      reasons.append('URL unusually long')
      score += 0.15


   # lots of digits
   if sum(c.isdigit() for c in u) > 8:
      reasons.append('Contains many digits')
      score += 0.1


   # hyphens in domain
   if '-' in te.domain:
      reasons.append('Hyphen in domain (common in lookalike domains)')
      score += 0.1


   # ip as host
   ip_match = re.search(r'https?://(\d{1,3}\.){3}\d{1,3}', u)
   if ip_match:
      reasons.append('Using IP address as host')
      score += 0.15


   # short TTL-like domains or many subdomains
   sub_count = 0 if not te.subdomain else te.subdomain.count('.') + 1
   if sub_count >= 3:
      reasons.append('Many subdomains (possible redirect/obfuscation)')
      score += 0.1


   # check for suspicious keywords
   suspicious_words = ['confirm', 'verify', 'account', 'secure', 'update', 'login', 'banking', 'pay', 'auth']
   lower = u.lower()
   for w in suspicious_words:
      if w in lower:
         reasons.append(f"Contains suspicious keyword: '{w}'")
         score += 0.05

   # try whois domain age (optional; can be slow)
   try:
      who = whois.whois(domain)
      if who and hasattr(who, 'creation_date') and who.creation_date:
         # handle list/date
         cdate = who.creation_date
         # if it's very new (e.g., less than 6 months) add to score
         import datetime
         if isinstance(cdate, list):
            cdate = cdate[0]
         if isinstance(cdate, datetime.datetime):
            age_days = (datetime.datetime.now() - cdate).days
            if age_days < 180:
               reasons.append('Domain registered recently')
               score += 0.1
   except Exception:
      # whois may fail; ignore silently to preserve responsiveness
      pass


   # limit score to 0..1
   score = min(score, 1.0)
   return score, reasons








