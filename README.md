# 🛡️ Phishing URL Sandbox Analyzer

A professional, user-friendly desktop application for analyzing suspicious URLs using VirusTotal's malware sandbox API. Extract Indicators of Compromise (IOCs) with a beautiful, modern GUI.

---

## 🎯 Features

- ✅ Submit URLs to VirusTotal for sandbox analysis
- ✅ Automatic polling for analysis completion
- ✅ Extract IOCs: IP addresses, domains, file hashes (MD5, SHA1, SHA256)
- ✅ Modern, cute GUI with a friendly feel
- ✅ Secure credential management via `.env`
- ✅ Rate-limit handling and error recovery
- ✅ Export results to structured JSON
- ✅ SOC/DFIR-ready output format

---

## 📋 Prerequisites

- Python 3.7 or higher
- VirusTotal API Key (Free)
- Internet connection

---

## 🔧 Step-by-Step Setup Guide

### Step 1: Create a VirusTotal Account

1. **Navigate to VirusTotal:**
   - Go to [https://www.virustotal.com/](https://www.virustotal.com/)

2. **Sign Up:**
   - Click **"Sign Up"** in the top-right corner
   - You can sign up using:
     - Google account
     - Email address
   - Complete the registration process

3. **Verify Your Email:**
   - Check your inbox and click the verification link

### Step 2: Generate Your API Key

1. **Log In:**
   - Sign in to your VirusTotal account

2. **Access Your Profile:**
   - Click your **profile icon** (top-right corner)
   - Select **"API Key"** from the dropdown menu

3. **Copy Your API Key:**
   - You'll see a long alphanumeric string (e.g., `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2`)
   - Click **"Copy"** to copy it to your clipboard
   - **⚠️ KEEP THIS SECRET** — Never share your API key publicly

### Step 3: Clone or Download This Project

```bash
# If using Git
git clone "https://github.com/Hari9602/Phishing-URL-Sandbox-Analyzer.git"
cd "Phishing URL Sandbox Analyzer"

# Or download and extract the ZIP file
```

### Step 4: Install Python Dependencies

```bash
# Install required packages
pip install -r requirements.txt
```

**Note:** If you encounter issues, try:
```bash
python -m pip install -r requirements.txt
```

### Step 5: Configure Your API Key

1. **Create a `.env` file** in the project root directory:
   ```bash
   # On Windows (PowerShell)
   New-Item .env -ItemType File

   # On Windows (Command Prompt)
   type nul > .env

   # On Linux/Mac
   touch .env
   ```

2. **Edit the `.env` file** and add your API key:
   ```env
   VIRUSTOTAL_API_KEY=your_actual_api_key_here
   ```

   **Example:**
   ```env
   VIRUSTOTAL_API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2
   ```

3. **Save the file**

4. **Security Check:**
   - ✅ `.env` is listed in `.gitignore` (never commit secrets!)
   - ✅ File permissions should be restricted (only you can read it)

### Step 6: Run the Application

```bash
python phishing_analyzer.py
```

The GUI window will open automatically!

---

## 🖥️ How to Use the Application

### 1. Launch the Application
- Run `python phishing_analyzer.py`
- A modern GUI window will appear

### 2. Enter URLs to Analyze
- Paste one or more URLs in the input field (one per line)
- Examples:
  ```
  http://suspicious-website.com
  https://phishing-example.net
  http://malware-test.org
  ```

### 3. Start Analysis
- Click the **"🔍 Analyze URLs"** button
- The app will:
  - Submit each URL to VirusTotal
  - Show real-time status updates
  - Poll for analysis completion
  - Extract IOCs automatically

### 4. View Results
- Results appear in the lower panel
- Includes:
  - ✅ Scan status (malicious/suspicious/clean)
  - 🌐 IP addresses
  - 🔗 Domains
  - 🔒 File hashes (MD5, SHA1, SHA256)

### 5. Export Results
- Results are **automatically saved** to `analysis_results.json`
- Use this file for:
  - SIEM ingestion
  - Threat intelligence platforms
  - Incident reports
  - Further analysis

---

## 📊 Understanding the Results

### Scan Status
- **Malicious:** Detected as a threat by multiple vendors
- **Suspicious:** Flagged by some vendors
- **Clean:** No threats detected
- **Unknown:** Analysis pending or unavailable

### IOCs Extracted
- **IP Addresses:** Associated IPs from network communications
- **Domains:** Contacted domains during analysis
- **Hashes:** File signatures (MD5, SHA1, SHA256)

---

## 🔒 Security Best Practices

1. **Never Share Your API Key**
   - Treat it like a password
   - Don't commit `.env` to Git
   - Don't paste it in screenshots

2. **Rate Limits (Free API)**
   - 4 requests per minute
   - 500 requests per day
   - The app handles rate limits automatically

3. **Test URLs Safely**
   - Only analyze URLs you suspect
   - Don't visit suspicious URLs directly
   - Use this tool in a VM if analyzing highly malicious content

---


---

## 🛠️ Troubleshooting

### "API key not found" Error
- ✅ Ensure `.env` file exists in the project root
- ✅ Check the file contains `VIRUSTOTAL_API_KEY=your_key`
- ✅ No spaces around the `=` sign
- ✅ No quotes around the key

### "Rate limit exceeded" Error
- ⏱️ Free API: 4 requests/minute
- Wait 60 seconds and try again
- The app will show a countdown timer

### GUI Doesn't Appear
- Install customtkinter: `pip install customtkinter`
- Try running: `python -m tkinter` to test Tkinter installation
- On Linux: `sudo apt-get install python3-tk`

### "Invalid URL" Error
- URLs must include protocol: `http://` or `https://`
- Check for typos
- Remove trailing spaces

### Dependencies Not Installing
```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Then install requirements
pip install -r requirements.txt
```

---

## 📦 Dependencies

- `requests` - HTTP API calls
- `python-dotenv` - Secure environment variable loading
- `customtkinter` - Modern GUI framework

---

## 🎨 GUI Design Philosophy

- **Modern:** Clean, contemporary interface
- **Cute:** Friendly colors and approachable design
- **Professional:** SOC/DFIR-ready functionality
- **Beginner-Friendly:** Clear labels and instructions
- **Responsive:** Real-time status updates

---

## 📝 Example Output (JSON)

```json
{
  "analysis_date": "2026-01-19T14:30:00Z",
  "total_urls_analyzed": 2,
  "results": [
    {
      "url": "http://suspicious-website.com",
      "scan_id": "u-abc123def456...",
      "status": "Malicious",
      "malicious_count": 45,
      "suspicious_count": 12,
      "total_engines": 90,
      "iocs": {
        "ip_addresses": ["192.168.1.100", "10.0.0.50"],
        "domains": ["evil-domain.com", "malware-cdn.net"],
        "hashes": {
          "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
          "sha1": ["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
          "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        }
      }
    }
  ]
}
```

---

## 🤝 Contributing

This is a production-ready tool for cybersecurity professionals. Feel free to enhance it with:
- Additional sandbox integrations (Hybrid Analysis, Any.Run)
- YARA rule scanning
- Automated threat intel enrichment
- MISP integration

---

## 📄 License

Use responsibly for legitimate security research and SOC operations only - see the [LICENSE](LICENSE) file for details. ⚖️

---

## 🆘 Support

- **VirusTotal API Docs:** [https://developers.virustotal.com/reference/overview](https://developers.virustotal.com/reference/overview)
- **Python Docs:** [https://docs.python.org/3/](https://docs.python.org/3/)

---

## ⚠️ Disclaimer

This tool is for **authorized security research and analysis only**. Always:
- Obtain proper authorization before analyzing URLs
- Follow your organization's security policies
- Comply with VirusTotal's Terms of Service
- Use in isolated environments when analyzing malicious content

**Happy Hunting! 🎯**
