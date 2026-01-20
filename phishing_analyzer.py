#!/usr/bin/env python3
import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv

try:
    import customtkinter as ctk
    from customtkinter import CTkFont
except ImportError:
    print("❌ Error: customtkinter not found.")
    print("📦 Install it with: pip install customtkinter")
    sys.exit(1)


class Config:
    VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
    API_TIMEOUT = 30
    RATE_LIMIT_DELAY = 15
    POLL_INTERVAL = 10
    MAX_POLL_ATTEMPTS = 30
    WINDOW_WIDTH = 900
    WINDOW_HEIGHT = 700
    WINDOW_TITLE = "🛡️ Phishing URL Sandbox Analyzer"
    COLOR_PRIMARY = "#6366f1"


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json"
        })
        self.last_request_time = 0
    
    def _rate_limit_wait(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < Config.RATE_LIMIT_DELAY:
            wait_time = Config.RATE_LIMIT_DELAY - elapsed
            time.sleep(wait_time)
        self.last_request_time = time.time()
    
    def submit_url(self, url: str) -> Optional[Dict[str, Any]]:
        self._rate_limit_wait()
        endpoint = f"{Config.VIRUSTOTAL_BASE_URL}/urls"
        
        try:
            response = self.session.post(endpoint, data={"url": url}, timeout=Config.API_TIMEOUT)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded. Please wait 60 seconds.")
            elif response.status_code == 401:
                raise Exception("Invalid API key. Check your .env file.")
            elif response.status_code == 403:
                raise Exception("Access forbidden. Check API key permissions.")
            else:
                raise Exception(f"API error: {response.status_code} - {response.text}")
        except requests.exceptions.Timeout:
            raise Exception("Request timed out. Check your internet connection.")
        except requests.exceptions.ConnectionError:
            raise Exception("Connection error. Check your internet connection.")
        except Exception as e:
            raise Exception(f"Failed to submit URL: {str(e)}")
    
    def get_url_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        self._rate_limit_wait()
        endpoint = f"{Config.VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}"
        
        try:
            response = self.session.get(endpoint, timeout=Config.API_TIMEOUT)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                raise Exception("Analysis not found.")
            else:
                raise Exception(f"API error: {response.status_code}")
        except Exception as e:
            raise Exception(f"Failed to get analysis: {str(e)}")
    
    def get_url_report(self, url: str) -> Optional[Dict[str, Any]]:
        self._rate_limit_wait()
        from base64 import urlsafe_b64encode
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"{Config.VIRUSTOTAL_BASE_URL}/urls/{url_id}"
        
        try:
            response = self.session.get(endpoint, timeout=Config.API_TIMEOUT)
            if response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception:
            return None
    
    def get_url_relationships(self, url_id: str, relationship: str, limit: int = 40) -> Optional[Dict[str, Any]]:
        self._rate_limit_wait()
        endpoint = f"{Config.VIRUSTOTAL_BASE_URL}/urls/{url_id}/{relationship}"
        
        try:
            response = self.session.get(endpoint, params={"limit": limit}, timeout=Config.API_TIMEOUT)
            if response.status_code == 200:
                return response.json()
            else:
                return None
        except Exception:
            return None


class IOCExtractor:
    @staticmethod
    def extract_from_relationships(client: 'VirusTotalClient', url_id: str) -> Dict[str, Any]:
        iocs = {
            "ip_addresses": set(),
            "domains": set(),
            "hashes": {
                "md5": set(),
                "sha1": set(),
                "sha256": set()
            }
        }
        
        try:
            contacted_ips = client.get_url_relationships(url_id, "contacted_ips")
            if contacted_ips and "data" in contacted_ips:
                for ip_data in contacted_ips["data"]:
                    if "id" in ip_data:
                        iocs["ip_addresses"].add(ip_data["id"])
            
            contacted_domains = client.get_url_relationships(url_id, "contacted_domains")
            if contacted_domains and "data" in contacted_domains:
                for domain_data in contacted_domains["data"]:
                    if "id" in domain_data:
                        iocs["domains"].add(domain_data["id"])
            
            contacted_urls = client.get_url_relationships(url_id, "contacted_urls")
            if contacted_urls and "data" in contacted_urls:
                for url_data in contacted_urls["data"]:
                    if "attributes" in url_data and "url" in url_data["attributes"]:
                        parsed = urlparse(url_data["attributes"]["url"])
                        if parsed.hostname:
                            iocs["domains"].add(parsed.hostname)
            
            redirecting = client.get_url_relationships(url_id, "redirecting_urls")
            if redirecting and "data" in redirecting:
                for url_data in redirecting["data"]:
                    if "attributes" in url_data and "url" in url_data["attributes"]:
                        parsed = urlparse(url_data["attributes"]["url"])
                        if parsed.hostname:
                            iocs["domains"].add(parsed.hostname)
            
            downloaded_files = client.get_url_relationships(url_id, "downloaded_files")
            if downloaded_files and "data" in downloaded_files:
                for file_data in downloaded_files["data"]:
                    attributes = file_data.get("attributes", {})
                    if "md5" in attributes:
                        iocs["hashes"]["md5"].add(attributes["md5"])
                    if "sha1" in attributes:
                        iocs["hashes"]["sha1"].add(attributes["sha1"])
                    if "sha256" in attributes:
                        iocs["hashes"]["sha256"].add(attributes["sha256"])
            
            related_files = client.get_url_relationships(url_id, "files")
            if related_files and "data" in related_files:
                for file_data in related_files["data"]:
                    attributes = file_data.get("attributes", {})
                    if "md5" in attributes:
                        iocs["hashes"]["md5"].add(attributes["md5"])
                    if "sha1" in attributes:
                        iocs["hashes"]["sha1"].add(attributes["sha1"])
                    if "sha256" in attributes:
                        iocs["hashes"]["sha256"].add(attributes["sha256"])
            
            resolutions = client.get_url_relationships(url_id, "resolutions")
            if resolutions and "data" in resolutions:
                for resolution_data in resolutions["data"]:
                    attributes = resolution_data.get("attributes", {})
                    if "ip_address" in attributes:
                        iocs["ip_addresses"].add(attributes["ip_address"])
                    if "host_name" in attributes:
                        iocs["domains"].add(attributes["host_name"])
        
        except Exception as e:
            print(f"⚠️ Error extracting IOCs from relationships: {e}")
        
        return {
            "ip_addresses": sorted(list(iocs["ip_addresses"])),
            "domains": sorted(list(iocs["domains"])),
            "hashes": {
                "md5": sorted(list(iocs["hashes"]["md5"])),
                "sha1": sorted(list(iocs["hashes"]["sha1"])),
                "sha256": sorted(list(iocs["hashes"]["sha256"]))
            }
        }
    
    @staticmethod
    def extract_from_url_report(data: Dict[str, Any]) -> Dict[str, Any]:
        iocs = {
            "ip_addresses": set(),
            "domains": set(),
            "hashes": {
                "md5": set(),
                "sha1": set(),
                "sha256": set()
            }
        }
        
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            if "last_final_url" in attributes:
                parsed = urlparse(attributes["last_final_url"])
                if parsed.hostname:
                    iocs["domains"].add(parsed.hostname)
            
            if "last_serving_ip_address" in attributes:
                iocs["ip_addresses"].add(attributes["last_serving_ip_address"])
        
        except Exception as e:
            print(f"⚠️ Error extracting IOCs from report: {e}")
        
        return {
            "ip_addresses": sorted(list(iocs["ip_addresses"])),
            "domains": sorted(list(iocs["domains"])),
            "hashes": {
                "md5": sorted(list(iocs["hashes"]["md5"])),
                "sha1": sorted(list(iocs["hashes"]["sha1"])),
                "sha256": sorted(list(iocs["hashes"]["sha256"]))
            }
        }


class URLAnalyzer:
    def __init__(self, api_key: str):
        self.client = VirusTotalClient(api_key)
        self.extractor = IOCExtractor()
    
    def analyze_url(self, url: str, status_callback=None) -> Dict[str, Any]:
        result = {
            "url": url,
            "domain": urlparse(url).hostname or "unknown",
            "scan_id": None,
            "status": "Unknown",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "total_engines": 0,
            "iocs": {
                "ip_addresses": [],
                "domains": [],
                "hashes": {"md5": [], "sha1": [], "sha256": []}
            },
            "error": None
        }
        
        try:
            if status_callback:
                status_callback(f"📤 Submitting: {url}")
            
            submission = self.client.submit_url(url)
            if not submission:
                result["error"] = "Failed to submit URL"
                return result
            
            analysis_id = submission.get("data", {}).get("id")
            result["scan_id"] = analysis_id
            
            if not analysis_id:
                result["error"] = "No analysis ID received"
                return result
            
            if status_callback:
                status_callback(f"⏳ Analyzing: {url} (this may take a minute)")
            
            analysis_data = None
            for attempt in range(Config.MAX_POLL_ATTEMPTS):
                time.sleep(Config.POLL_INTERVAL)
                
                if status_callback:
                    status_callback(f"⏳ Waiting for results... ({attempt + 1}/{Config.MAX_POLL_ATTEMPTS})")
                
                analysis_data = self.client.get_url_analysis(analysis_id)
                
                if analysis_data:
                    status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        break
            
            if not analysis_data:
                result["error"] = "Analysis timeout"
                return result
            
            attributes = analysis_data.get("data", {}).get("attributes", {})
            stats = attributes.get("stats", {})
            
            result["malicious_count"] = stats.get("malicious", 0)
            result["suspicious_count"] = stats.get("suspicious", 0)
            result["harmless_count"] = stats.get("harmless", 0)
            result["undetected_count"] = stats.get("undetected", 0)
            result["total_engines"] = sum(stats.values())
            
            if result["malicious_count"] > 0:
                result["status"] = "Malicious"
            elif result["suspicious_count"] > 0:
                result["status"] = "Suspicious"
            elif result["harmless_count"] > 0:
                result["status"] = "Clean"
            else:
                result["status"] = "Unknown"
            
            if status_callback:
                status_callback(f"🔍 Extracting IOCs: {url}")
            
            from base64 import urlsafe_b64encode
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            
            iocs = self.extractor.extract_from_relationships(self.client, url_id)
            result["iocs"] = iocs
            
            try:
                url_report = self.client.get_url_report(url)
                if url_report:
                    report_iocs = self.extractor.extract_from_url_report(url_report)
                    all_ips = set(result["iocs"]["ip_addresses"]) | set(report_iocs["ip_addresses"])
                    all_domains = set(result["iocs"]["domains"]) | set(report_iocs["domains"])
                    all_md5 = set(result["iocs"]["hashes"]["md5"]) | set(report_iocs["hashes"]["md5"])
                    all_sha1 = set(result["iocs"]["hashes"]["sha1"]) | set(report_iocs["hashes"]["sha1"])
                    all_sha256 = set(result["iocs"]["hashes"]["sha256"]) | set(report_iocs["hashes"]["sha256"])
                    
                    result["iocs"]["ip_addresses"] = sorted(list(all_ips))
                    result["iocs"]["domains"] = sorted(list(all_domains))
                    result["iocs"]["hashes"]["md5"] = sorted(list(all_md5))
                    result["iocs"]["hashes"]["sha1"] = sorted(list(all_sha1))
                    result["iocs"]["hashes"]["sha256"] = sorted(list(all_sha256))
            except Exception:
                pass
            
            if status_callback:
                status_callback(f"✅ Completed: {url} - {result['status']}")
            
        except Exception as e:
            result["error"] = str(e)
            if status_callback:
                status_callback(f"❌ Error: {url} - {str(e)}")
        
        return result


class PhishingAnalyzerGUI:
    def __init__(self, api_key: str):
        self.analyzer = URLAnalyzer(api_key)
        self.is_analyzing = False
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.window = ctk.CTk()
        self.window.title(Config.WINDOW_TITLE)
        self.window.geometry(f"{Config.WINDOW_WIDTH}x{Config.WINDOW_HEIGHT}")
        self._create_ui()
    
    def _create_ui(self):
        main_frame = ctk.CTkFrame(self.window, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))
        
        title_label = ctk.CTkLabel(header_frame, text="🛡️ Phishing URL Sandbox Analyzer", font=CTkFont(size=24, weight="bold"))
        title_label.pack()
        
        subtitle_label = ctk.CTkLabel(header_frame, text="Analyze suspicious URLs with VirusTotal • Extract IOCs • Stay Safe", font=CTkFont(size=12), text_color="gray")
        subtitle_label.pack()
        
        input_frame = ctk.CTkFrame(main_frame)
        input_frame.pack(fill="x", pady=(0, 20))
        
        input_label = ctk.CTkLabel(input_frame, text="📝 Enter URLs to Analyze (one per line):", font=CTkFont(size=14, weight="bold"), anchor="w")
        input_label.pack(fill="x", padx=15, pady=(15, 5))
        
        self.url_input = ctk.CTkTextbox(input_frame, height=120, font=CTkFont(size=12), wrap="word")
        self.url_input.pack(fill="x", padx=15, pady=(0, 15))
        self.url_input.insert("1.0", "# Paste suspicious URLs here, one per line\n# Example:\n# http://suspicious-website.com\n# https://phishing-example.net")
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=(0, 20))
        
        self.analyze_button = ctk.CTkButton(button_frame, text="🔍 Analyze URLs", font=CTkFont(size=16, weight="bold"), height=45, command=self._on_analyze_click, fg_color=Config.COLOR_PRIMARY, hover_color="#5558d9")
        self.analyze_button.pack(side="left", expand=True, fill="x", padx=(0, 5))
        
        self.clear_button = ctk.CTkButton(button_frame, text="🗑️ Clear", font=CTkFont(size=16), height=45, command=self._on_clear_click, fg_color="gray40", hover_color="gray30")
        self.clear_button.pack(side="left", padx=(5, 0))
        
        status_frame = ctk.CTkFrame(main_frame)
        status_frame.pack(fill="x", pady=(0, 20))
        
        status_label = ctk.CTkLabel(status_frame, text="📊 Status:", font=CTkFont(size=14, weight="bold"), anchor="w")
        status_label.pack(fill="x", padx=15, pady=(15, 5))
        
        self.status_text = ctk.CTkTextbox(status_frame, height=100, font=CTkFont(size=11), wrap="word", state="disabled")
        self.status_text.pack(fill="x", padx=15, pady=(0, 15))
        
        results_frame = ctk.CTkFrame(main_frame)
        results_frame.pack(fill="both", expand=True)
        
        results_label = ctk.CTkLabel(results_frame, text="📋 Analysis Results:", font=CTkFont(size=14, weight="bold"), anchor="w")
        results_label.pack(fill="x", padx=15, pady=(15, 5))
        
        self.results_text = ctk.CTkTextbox(results_frame, font=CTkFont(size=11), wrap="word", state="disabled")
        self.results_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self._update_status("Ready to analyze URLs. Enter URLs above and click 'Analyze'.")
    
    def _update_status(self, message: str):
        self.status_text.configure(state="normal")
        self.status_text.insert("end", f"{message}\n")
        self.status_text.see("end")
        self.status_text.configure(state="disabled")
        self.window.update()
    
    def _update_results(self, message: str):
        self.results_text.configure(state="normal")
        self.results_text.insert("end", f"{message}\n")
        self.results_text.see("end")
        self.results_text.configure(state="disabled")
        self.window.update()
    
    def _clear_results(self):
        self.results_text.configure(state="normal")
        self.results_text.delete("1.0", "end")
        self.results_text.configure(state="disabled")
    
    def _on_clear_click(self):
        self.url_input.delete("1.0", "end")
        self._clear_results()
        self.status_text.configure(state="normal")
        self.status_text.delete("1.0", "end")
        self.status_text.configure(state="disabled")
        self._update_status("Cleared. Ready for new analysis.")
    
    def _on_analyze_click(self):
        if self.is_analyzing:
            self._update_status("⚠️ Analysis already in progress...")
            return
        
        url_text = self.url_input.get("1.0", "end").strip()
        urls = []
        for line in url_text.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
        
        if not urls:
            self._update_status("❌ No URLs entered. Please enter at least one URL.")
            return
        
        valid_urls = []
        for url in urls:
            if url.startswith("http://") or url.startswith("https://"):
                valid_urls.append(url)
            else:
                self._update_status(f"⚠️ Skipping invalid URL (missing http/https): {url}")
        
        if not valid_urls:
            self._update_status("❌ No valid URLs found. URLs must start with http:// or https://")
            return
        
        self.is_analyzing = True
        self.analyze_button.configure(state="disabled", text="⏳ Analyzing...")
        self._clear_results()
        self._update_status(f"\n{'='*60}")
        self._update_status(f"🚀 Starting analysis of {len(valid_urls)} URL(s)")
        self._update_status(f"{'='*60}\n")
        
        all_results = []
        for idx, url in enumerate(valid_urls, 1):
            self._update_status(f"\n[{idx}/{len(valid_urls)}] Processing: {url}")
            result = self.analyzer.analyze_url(url, status_callback=self._update_status)
            all_results.append(result)
            self._display_result(result)
        
        self._save_results(all_results)
        self.is_analyzing = False
        self.analyze_button.configure(state="normal", text="🔍 Analyze URLs")
        self._update_status(f"\n{'='*60}")
        self._update_status(f"✅ Analysis complete! Results saved to report/ folder")
        self._update_status(f"{'='*60}")
    
    def _display_result(self, result: Dict[str, Any]):
        self._update_results("\n" + "="*70)
        self._update_results(f"🔗 URL: {result['url']}")
        self._update_results("="*70)
        
        if result.get("error"):
            self._update_results(f"❌ Error: {result['error']}")
            return
        
        status_emoji = {"Malicious": "🔴", "Suspicious": "🟡", "Clean": "🟢", "Unknown": "⚪"}
        emoji = status_emoji.get(result["status"], "⚪")
        
        self._update_results(f"{emoji} Status: {result['status']}")
        self._update_results(f"📊 Detection: {result['malicious_count']} malicious, {result['suspicious_count']} suspicious, {result['harmless_count']} harmless (out of {result['total_engines']} engines)")
        
        iocs = result.get("iocs", {})
        self._update_results(f"\n🌐 IP Addresses ({len(iocs.get('ip_addresses', []))}):")
        if iocs.get("ip_addresses"):
            for ip in iocs["ip_addresses"]:
                self._update_results(f"   • {ip}")
        else:
            self._update_results("   (none detected)")
        
        self._update_results(f"\n🔗 Domains ({len(iocs.get('domains', []))}):")
        if iocs.get("domains"):
            for domain in iocs["domains"]:
                self._update_results(f"   • {domain}")
        else:
            self._update_results("   (none detected)")
        
        hashes = iocs.get("hashes", {})
        total_hashes = len(hashes.get("md5", [])) + len(hashes.get("sha1", [])) + len(hashes.get("sha256", []))
        self._update_results(f"\n🔒 File Hashes ({total_hashes}):")
        if total_hashes > 0:
            for md5 in hashes.get("md5", []):
                self._update_results(f"   • MD5: {md5}")
            for sha1 in hashes.get("sha1", []):
                self._update_results(f"   • SHA1: {sha1}")
            for sha256 in hashes.get("sha256", []):
                self._update_results(f"   • SHA256: {sha256}")
        else:
            self._update_results("   (none detected)")
    
    def _save_results(self, results: List[Dict[str, Any]]):
        report_dir = "report"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%d")
        
        for result in results:
            domain = result.get("domain", "unknown").replace(":", "_").replace("/", "_")
            filename = f"{timestamp}_{domain}_analysis.json"
            filepath = os.path.join(report_dir, filename)
            
            output = {
                "analysis_date": datetime.utcnow().isoformat() + "Z",
                "url": result["url"],
                "domain": result.get("domain", "unknown"),
                "scan_id": result.get("scan_id"),
                "status": result["status"],
                "detection": {
                    "malicious": result["malicious_count"],
                    "suspicious": result["suspicious_count"],
                    "harmless": result["harmless_count"],
                    "undetected": result["undetected_count"],
                    "total_engines": result["total_engines"]
                },
                "iocs": result["iocs"],
                "error": result.get("error")
            }
            
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(output, f, indent=2, ensure_ascii=False)
                self._update_status(f"💾 Report saved: {filepath}")
            except Exception as e:
                self._update_status(f"❌ Failed to save report for {domain}: {e}")
        
        combined_output = {
            "analysis_date": datetime.utcnow().isoformat() + "Z",
            "total_urls_analyzed": len(results),
            "results": results
        }
        
        combined_filepath = os.path.join(report_dir, f"{timestamp}_combined_analysis.json")
        try:
            with open(combined_filepath, "w", encoding="utf-8") as f:
                json.dump(combined_output, f, indent=2, ensure_ascii=False)
            self._update_status(f"💾 Combined report saved: {combined_filepath}")
        except Exception as e:
            self._update_status(f"❌ Failed to save combined report: {e}")
    
    def run(self):
        self.window.mainloop()


def load_api_key() -> Optional[str]:
    load_dotenv()
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key or api_key == "your_actual_virustotal_api_key_here_64_characters_long_string":
        return None
    return api_key


def main():
    print("\n" + "="*70)
    print("🛡️  Phishing URL Sandbox Analyzer")
    print("="*70)
    print("🔒 Security Tool for Phishing Detection & IOC Extraction")
    print("📅 January 2026")
    print("="*70 + "\n")
    
    print("🔑 Loading VirusTotal API key...")
    api_key = load_api_key()
    
    if not api_key:
        print("\n❌ ERROR: VirusTotal API key not found!\n")
        print("📋 Setup Instructions:")
        print("   1. Create a .env file in the project directory")
        print("   2. Add this line: VIRUSTOTAL_API_KEY=your_actual_key_here")
        print("   3. Get your API key from: https://www.virustotal.com/")
        print("\n💡 See README.md for detailed setup instructions.\n")
        input("Press Enter to exit...")
        sys.exit(1)
    
    print("✅ API key loaded successfully!\n")
    print("🚀 Launching GUI application...\n")
    
    try:
        app = PhishingAnalyzerGUI(api_key)
        app.run()
    except KeyboardInterrupt:
        print("\n\n👋 Application closed by user.")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")
        sys.exit(1)


if __name__ == "__main__":
    main()
