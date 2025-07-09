
### 📁 `README.md` — Exploiting XXE by Repurposing a Local DTD (Expert Level)

# 🔥 Exploiting Blind XXE by Repurposing a Local DTD

**🧪 Lab Level:** Expert  
**🔐 Vulnerability:** Blind XXE via local DTD repurposing and error-based data leak  
**✅ Status:** Solved  
**🛠 Platform:** PortSwigger Web Security Academy  
**🎯 Objective:** Leak `/etc/passwd` by referencing and redefining an existing local DTD entity to trigger an error message containing sensitive data.

---

## 🔍 Lab Overview

The application parses XML input in a "Check stock" feature but does **not display the parsed output**.

The key is to use a **hybrid internal-external DTD attack** by referencing an existing DTD file on the server (`/usr/share/yelp/dtd/docbookx.dtd`) which defines an entity called `ISOamso`.  
By redefining this entity internally, you can bypass the usual XML parser restrictions and trigger an error message that leaks `/etc/passwd`.

---

## ⚙️ Exploitation Steps

### 1. 🕵️ Intercept the Request

On a product page, click **“Check stock”**, and intercept the POST request in Burp Suite.

---

### 2. 📥 Inject the Malicious DTD Declaration

Replace or insert the following DOCTYPE declaration **between** the XML declaration and `<stockCheck>` element:

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/%file;&#x27;>">
    %eval;
    %error;
  '>
  %local_dtd;
]>
````

## 📸 Screenshots

Here are some screenshots demonstrating the successful exploitation of the XXE via SVG image upload lab:

![XXE](https://github.com/Kabilala/xxe/blob/main/lab9/lab9.png)


---

### 3. 📡 Trigger the Payload

Send the modified XML request.

What happens:

* The external DTD (`docbookx.dtd`) is loaded from the local filesystem
* The `ISOamso` entity is redefined internally to include an error-triggering entity that tries to load a non-existent file path containing the contents of `/etc/passwd`
* The parser throws an error message containing the contents of `/etc/passwd` in the error text

---

## 🧠 Technical Explanation

| Entity Name        | Purpose                                                              |
| ------------------ | -------------------------------------------------------------------- |
| `%local_dtd`       | Loads the external DTD file locally from server filesystem           |
| `%ISOamso`         | Redefines the existing entity to execute the error-based XXE payload |
| `%file`            | Reads the sensitive file `/etc/passwd`                               |
| `%eval` & `%error` | Triggers an invalid file inclusion to force an error leak            |

This hybrid approach circumvents the XML spec limitation on nested parameter entities by leveraging a local external DTD file.

---

## 🔐 Mitigation Tips

* Disable or restrict **external DTD loading** on XML parsers
* Use **secure XML parsing libraries** with DTD and entity expansion disabled
* Monitor logs for abnormal error messages or excessive file access attempts
* Implement strong **input validation** and **least privilege** for XML processing

---