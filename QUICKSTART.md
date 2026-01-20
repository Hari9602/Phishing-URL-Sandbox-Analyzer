# ⚡ Quick Start Guide

## 🚀 Fast Setup (5 Minutes)

### 1. Get VirusTotal API Key
1. Go to https://www.virustotal.com/
2. Sign up (free)
3. Click your profile → "API Key"
4. Copy the key

### 2. Configure
```bash
# Copy the example file
copy .env.example .env

# Edit .env and paste your API key
VIRUSTOTAL_API_KEY=paste_your_key_here
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run
**Windows:**
```bash
run.bat
# Or double-click run.bat
```

**Linux/Mac:**
```bash
chmod +x run.sh
./run.sh
```

**Or directly:**
```bash
python phishing_analyzer.py
```

---

## 📱 Using the Application

1. **Enter URLs** (one per line):
   ```
   http://suspicious-website.com
   https://phishing-example.net
   ```

2. **Click "Analyze URLs"**

3. **Wait for results** (30-60 seconds per URL)

4. **View Results:**
   - Status (Malicious/Suspicious/Clean)
   - IP addresses
   - Domains
   - File hashes

5. **Results auto-saved** to `analysis_results.json`

---

## 🔒 Security Notes

- ✅ API key stored in `.env` (never commit)
- ✅ Free tier: 4 requests/minute, 500/day
- ✅ App handles rate limits automatically

---

## ❓ Troubleshooting

**"API key not found"**
- Create `.env` file
- Add: `VIRUSTOTAL_API_KEY=your_key`

**"Rate limit exceeded"**
- Wait 60 seconds
- Free tier limit reached

**GUI doesn't appear**
```bash
pip install customtkinter
```

---

## 📊 Example Output

Results include:
- 🔴 Malicious / 🟡 Suspicious / 🟢 Clean status
- 🌐 IP addresses contacted
- 🔗 Domains involved
- 🔒 File hashes (MD5, SHA1, SHA256)
- 💾 JSON export for SIEM/TIP integration

---

**Full documentation:** See [README.md](README.md)
