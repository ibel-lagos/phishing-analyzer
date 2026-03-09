# 📧 Phishing Email Analyzer

A Python-based tool that analyzes **email headers** to detect potential **phishing indicators automatically**.

This project was built as part of my **cybersecurity portfolio** to demonstrate practical skills related to **SOC Analyst tasks**, email threat analysis, and phishing detection.

---

# 🎯 Project Goal

Phishing attacks remain one of the most common **initial access techniques** used in cyber attacks.

This tool helps identify **warning signs in email headers**, automating some of the basic checks a **security analyst** would normally perform during an investigation.

---

# 🔍 Features

The analyzer automatically detects:

* ❌ **SPF authentication failures**
* ⚠️ **Missing DKIM signatures**
* 🔁 **Mismatched FROM and REPLY-TO domains**
* 🚩 **Suspicious top-level domains**, such as:

  * `.ru`
  * `.xyz`
  * `.tk`
  * `.top`
  * `.click`
  * `.ml`

The tool also calculates a **Risk Score** to estimate the threat level of the analyzed email.

---
## 🛠️ Built With

| Tool | Details |
|------|---------|
| 🐧 OS | Ubuntu Linux |
| 💻 Terminal | Bash |
| 📝 Editor | VSCode |
| 🐍 Language | Python 3 |
| 📚 Libraries | email · re (Standard Library) |

This project was intentionally built **without external dependencies** to keep it simple, portable, and easy to run.

---

# 🚀 How to Use

## 1️⃣ Get the email headers

In **Gmail**:

1. Open the email
2. Click the **three dots ⋮** in the top-right corner
3. Select **Show original**
4. Click **Copy to clipboard**

---

## 2️⃣ Save the email content

Paste the copied headers into a file named:

```
sample_email.txt
```

---

## 3️⃣ Run the analyzer

```bash
python3 analyzer.py
```

---

# 📊 Example Output

```
EMAIL PHISHING ANALYZER
========================================
FROM:         "PayPal Security" <security@paypal-verify.tk>
REPLY-TO:     hacker@malicious.ru
SPF:          fail
DKIM:         Missing

ALERTS:
 - SPF FAIL - sender is not authorized
 - Suspicious domain detected: paypal-verify.tk
 - Suspicious domain detected: malicious.ru

RISK SCORE: 8
VERDICT: DANGEROUS - Possible phishing attempt
========================================
```

---

# 🔮 Possible Future Improvements

* Detect **DMARC failures**
* Analyze **Received headers**
* Detect **suspicious IP addresses**
* Integrate with **VirusTotal API**
* Add a **web interface for automatic analysis**

---

# 👩‍💻 Author

**Ibel Lagos**

🌐 Portfolio
https://ibel-lagos.github.io/my-page-web
