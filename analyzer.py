import email
import re

# Load email from a .txt file containing raw email headers
def load_email(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        raw = f.read()
    return email.message_from_string(raw)

# Extract relevant security headers from the email
def extract_headers(msg):
    return {
        'from': msg.get('From'),
        'reply_to': msg.get('Reply-To'),
        'return_path': msg.get('Return-Path'),
        'received': msg.get_all('Received'),
        'spf': msg.get('Received-SPF'),
        'dkim': msg.get('DKIM-Signature'),
    }

# Extract domain name from an email address string
def extract_domain(email_str):
    if not email_str:
        return None
    match = re.search(r'@([\w\.-]+)', email_str)
    return match.group(1).lower() if match else None

# Analyze headers and return alerts and a risk score
def analyze(headers):
    alerts = []
    score = 0

    # Check SPF result
    if headers['spf'] and 'fail' in headers['spf'].lower():
        alerts.append("SPF FAIL - sender is not authorized")
        score += 2

    # Check DKIM presence
    if not headers['dkim']:
        alerts.append("DKIM missing - email is not signed")
        score += 2

    # Check if FROM and REPLY-TO domains differ
    from_domain = extract_domain(headers['from'])
    reply_domain = extract_domain(headers['reply_to'])
    if from_domain and reply_domain and from_domain != reply_domain:
        alerts.append(f"FROM ({from_domain}) and REPLY-TO ({reply_domain}) have different domains")
        score += 3

    # Check for suspicious top-level domains
    suspicious_tlds = ['.ru', '.xyz', '.tk', '.top', '.click', '.ml']
    all_domains = [from_domain, reply_domain, extract_domain(headers['return_path'])]
    for domain in all_domains:
        if domain:
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    alerts.append(f"Suspicious domain detected: {domain}")
                    score += 3

    return alerts, score

# Return a human-readable verdict based on the risk score
def verdict(score):
    if score == 0:
        return "CLEAN - No phishing signals detected"
    elif score <= 3:
        return "SUSPICIOUS - Manual review recommended"
    else:
        return "DANGEROUS - Possible phishing attempt"

# --- Main ---
msg = load_email('sample_email.txt')
headers = extract_headers(msg)

print("\nEMAIL PHISHING ANALYZER")
print("=" * 40)
print(f"FROM:         {headers['from']}")
print(f"REPLY-TO:     {headers['reply_to']}")
print(f"RETURN-PATH:  {headers['return_path']}")
print(f"SPF:          {headers['spf']}")
print(f"DKIM:         {'Present' if headers['dkim'] else 'Missing'}")

print("\nALERTS:")
alerts, score = analyze(headers)
if alerts:
    for alert in alerts:
        print(f"  - {alert}")
else:
    print("  None")

print(f"\nRISK SCORE: {score}")
print(f"VERDICT: {verdict(score)}")
print("=" * 40)
