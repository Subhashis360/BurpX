
<h1 align="center">
  <img src="https://github.com/Subhashis360/BurpX/blob/main/logo.png" alt="BurpX" width="200px">
  <br>
</h1>

<h4 align="center">🚀 Advanced Security Extension for Burp Suite - Detects SQLi, SSRF, SSTI & more!</h4>

<p align="center">
<a href="https://github.com/Subhashis360/BurpX/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/Subhashis360/BurpX/releases"><img src="https://img.shields.io/github/release/Subhashis360/BurpX"></a>
<a href="https://twitter.com/smtechyt2"><img src="https://img.shields.io/twitter/follow/SubhashisSec.svg?logo=twitter"></a>
</p>

<p align="center">
  <a href="#features">🔥 Features</a> •
  <a href="#installation">💻 Installation</a> •
  <a href="#how-it-works">⚙️ How it Works</a> •
  <a href="#demo">🎞️ Demo</a> •
  <a href="#license">📜 License</a>
</p>

---

`BurpX` is a powerful extension for Burp Suite designed to automatically detect and alert on vulnerabilities such as SQL Injection (SQLi), Server-Side Request Forgery (SSRF), Server-Side Template Injection (SSTI), and more.

## 🚀 Features

- 🧠 Intelligent scanning for multiple attack vectors
- ⚡ Real-time alerting and logging
- 🛡️ Customizable signature and payload support
- 📊 Animated visualization of injection points (GitHub Actions)
- 🧩 Easy integration into existing Burp Suite setup
- 💾 Exportable reports for all findings

## 💻 Installation

1. Open **Burp Suite**.
2. Navigate to **Extender > Extensions > Add**.
3. Set **Extension type** to `Python` or `Java` (depending on your version).
4. Select the `BurpX.py` or `BurpX.jar` file.
5. Click **Next** and you're ready to go!

🔧 Make sure Burp is configured with Jython standalone jar if using Python extensions.

## ⚙️ How it Works

BurpX works by passively and actively scanning HTTP traffic for vulnerable parameters, forms, and URLs. It uses:
- Payload-based detection using carefully curated strings
- Timing attacks for blind SQLi
- SSRF endpoint detection via DNS & IP response analysis
- SSTI fuzzing with template syntax injection

## 🎞️ Demo

![BurpX demo](https://github.com/Subhashis360/BurpX/blob/main/demo.png)

> More demo GIFs and advanced usage guides are available in the [Wiki](https://github.com/Subhashis360/BurpX/wiki).

## 🔐 Supported Vulnerabilities

- ✅ SQL Injection (Boolean, Error-based, Time-based) ( soon )
- ✅ SSRF (Internal IP detection, SSRF chains) ( soon )
- ✅ SSTI (Jinja2, Velocity, Twig) 
- ✅ Command Injection (Experimental) ( soon )
- ✅ Open Redirects, Header Injections ( soon )

## 📜 License

MIT License

---

Made with 🧠 + ☕ by [Subhashis360](https://github.com/Subhashis360) — Contributions are welcome!

🔗 Follow me on Twitter: [@subhashis](https://twitter.com/smtechyt2)
🛠️ Join the community: Coming Soon!

