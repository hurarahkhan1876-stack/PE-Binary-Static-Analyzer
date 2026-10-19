# PE-Binary-Static-Analyzer
Low-level Python static analyzer for inspecting Windows PE headers, COFF metadata, and Shannon Entropy.
# PE Binary Static Analyzer 🛡️

**Author:** Muhammad Hurairah (Z1 CH3N)  
**Field:** ADP Computer Networking  

## 📌 Overview
A lightweight, low-level static analysis tool built in Python for inspecting Windows Portable Executable (`.exe` / `.dll`) binaries. The script parses MS-DOS headers, locates PE signatures via binary struct unpacking at memory offsets, extracts COFF architecture metadata, and calculates Shannon Entropy to detect packed or obfuscated code.

## ⚙️ Key Technical Features
- **Binary Header Parsing:** Unpacking raw byte structures using Python's native `struct` library.
- **Architecture & Section Extraction:** Reading x86/x64 flags, section counts, and compilation timestamps directly from PE header bytes.
- **Entropy Calculation:** Computing Shannon Entropy ($0.0 - 8.0$) to flag encrypted payloads or malware packers.

## 💻 Proof of Execution
![PE Analyzer Output](Screenshot_2026-10-19_185837.png)

## 🚀 Usage
```bash
python pe_analyzer.py
