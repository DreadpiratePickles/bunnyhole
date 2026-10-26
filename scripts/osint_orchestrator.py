#!/usr/bin/env python3
"""
OSINT Orchestrator & Pipeline Engine
Takes input data (email, username, domain, IP, phone, hash) and:
1. Runs it through all available free OSINT tools
2. Calls free APIs and web services
3. Pipes output between tools (e.g., email -> usernames -> social profiles)
4. Correlates results into a unified JSON report

Usage:
  python3 osint_orchestrator.py --target <value> --type <email|username|domain|ip|phone|hash>
  python3 osint_orchestrator.py --target john@example.com --type email
  python3 osint_orchestrator.py --target johndoe --type username --deep
  python3 osint_orchestrator.py --target example.com --type domain --output report.json
"""

import argparse
import json
import os
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import quote

import requests

# Load API keys from env file if present
API_ENV_FILE = os.path.expanduser("~/.osint-apis/api_keys.env")
if os.path.exists(API_ENV_FILE):
    with open(API_ENV_FILE) as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, val = line.strip().split('=', 1)
                os.environ.setdefault(key, val)

# ============ CONFIGURATION ============
TIMEOUT = 30
MAX_WORKERS = 10
USER_AGENT = "OSINT-Orchestrator/2.0 (Research)"

# Free API endpoints (no key or free tier)
FREE_APIS = {
    # Breach & Leak
    "breachdirectory": {
        "url": "https://breachdirectory.com/api/api/domain/{target}",
        "needs_key": False,
        "type": ["email", "domain", "username"]
    },
    "hudsonrock": {
        "url": "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-keyword?keyword={target}",
        "needs_key": False,
        "type": ["email", "username", "domain", "ip"]
    },
    "intelx_free": {
        "url": "https://public.intelx.io/api/v1/search?query={target}",
        "needs_key": False,
        "type": ["email", "domain", "username", "ip"]
    },

    # Infrastructure
    "ipinfo": {
        "url": "https://ipinfo.io/{target}/json",
        "needs_key": False,
        "type": ["ip"]
    },
    "ipapi": {
        "url": "http://ip-api.com/json/{target}",
        "needs_key": False,
        "type": ["ip"]
    },
    "ipgeolocation": {
        "url": "https://api.ipgeolocation.io/ipgeo?apiKey={key}&ip={target}",
        "needs_key": True,
        "env_key": "IPGEOLOCATION_API_KEY",
        "type": ["ip"]
    },
    "bgpview": {
        "url": "https://api.bgpview.io/ip/{target}",
        "needs_key": False,
        "type": ["ip"]
    },
    "bgpview_prefix": {
        "url": "https://api.bgpview.io/prefix/{target}",
        "needs_key": False,
        "type": ["ip"]
    },
    "domainsdb": {
        "url": "https://api.domainsdb.info/v1/domains/search?domain={target}&zone=com",
        "needs_key": False,
        "type": ["domain"]
    },
    "crtsh": {
        "url": "https://crt.sh/?q=%.{target}&output=json",
        "needs_key": False,
        "type": ["domain"]
    },
    "threatcrowd_domain": {
        "url": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}",
        "needs_key": False,
        "type": ["domain"]
    },
    "threatcrowd_ip": {
        "url": "https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={target}",
        "needs_key": False,
        "type": ["ip"]
    },
    "urlscan": {
        "url": "https://urlscan.io/api/v1/search/?q=domain:{target}",
        "needs_key": False,
        "type": ["domain"]
    },
    "abuseipdb": {
        "url": "https://api.abuseipdb.com/api/v2/check?ipAddress={target}",
        "needs_key": True,
        "env_key": "ABUSEIPDB_API_KEY",
        "headers": {"Key": "{key}"},
        "type": ["ip"]
    },
    "alienvault_otx": {
        "url": "https://otx.alienvault.com/api/v1/indicators/{type}/{target}/general",
        "needs_key": False,
        "type": ["ip", "domain"],
        "dynamic_type": True
    },
    "virustotal_domain": {
        "url": "https://www.virustotal.com/api/v3/domains/{target}",
        "needs_key": True,
        "env_key": "VIRUSTOTAL_API_KEY",
        "headers": {"x-apikey": "{key}"},
        "type": ["domain"]
    },
    "virustotal_ip": {
        "url": "https://www.virustotal.com/api/v3/ip_addresses/{target}",
        "needs_key": True,
        "env_key": "VIRUSTOTAL_API_KEY",
        "headers": {"x-apikey": "{key}"},
        "type": ["ip"]
    },
    "shodan_host": {
        "url": "https://api.shodan.io/shodan/host/{target}?key={key}",
        "needs_key": True,
        "env_key": "SHODAN_API_KEY",
        "type": ["ip"]
    },
    "shodan_domain": {
        "url": "https://api.shodan.io/dns/domain/{target}?key={key}",
        "needs_key": True,
        "env_key": "SHODAN_API_KEY",
        "type": ["domain"]
    },
    "censys_host": {
        "url": "https://search.censys.io/api/v2/hosts/{target}",
        "needs_key": True,
        "env_key": "CENSYS_API_ID",
        "auth": "basic",
        "type": ["ip"]
    },

    # Email
    "kickbox": {
        "url": "https://api.kickbox.com/v2/verify?email={target}&apikey={key}",
        "needs_key": False,
        "type": ["email"]
    },
    "emailrep": {
        "url": "https://emailrep.io/{target}",
        "needs_key": False,
        "type": ["email"]
    },
    "haveibeenpwned": {
        "url": "https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
        "needs_key": True,
        "env_key": "HAVEIBEENPWNED_API_KEY",
        "headers": {"hibp-api-key": "{key}", "User-Agent": "OSINT-Orchestrator"},
        "type": ["email"]
    },
    "hunter": {
        "url": "https://api.hunter.io/v2/domain-search?domain={target}&api_key={key}",
        "needs_key": True,
        "env_key": "HUNTER_API_KEY",
        "type": ["domain"]
    },

    # Social & Identity
    "github_user": {
        "url": "https://api.github.com/users/{target}",
        "needs_key": False,
        "type": ["username"]
    },
    "github_search": {
        "url": "https://api.github.com/search/users?q={target}",
        "needs_key": False,
        "type": ["username", "email"]
    },

    # Phone
    "numverify": {
        "url": "http://apilayer.net/api/validate?access_key={key}&number={target}",
        "needs_key": True,
        "env_key": "NUMVERIFY_API_KEY",
        "type": ["phone"]
    },

    # Hash/Malware
    "virustotal_hash": {
        "url": "https://www.virustotal.com/api/v3/files/{target}",
        "needs_key": True,
        "env_key": "VIRUSTOTAL_API_KEY",
        "headers": {"x-apikey": "{key}"},
        "type": ["hash"]
    },
    "malwarebazaar": {
        "url": "https://mb-api.abuse.ch/api/v1/",
        "method": "POST",
        "data": {"query": "get_info", "hash": "{target}"},
        "needs_key": False,
        "type": ["hash"]
    },
}

# ============ TOOL RUNNERS ============

def run_shell_tool(cmd, timeout=TIMEOUT):
    """Execute a shell command and return parsed output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, executable='/bin/bash'
        )
        return {
            "command": cmd,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {"command": cmd, "success": False, "error": "Timeout"}
    except Exception as e:
        return {"command": cmd, "success": False, "error": str(e)}

def run_sherlock(username):
    """Run Sherlock username search."""
    output_file = f"/tmp/sherlock_{username}_{int(time.time())}.json"
    cmd = f'sherlock "{username}" --json "{output_file}" --timeout 10 --print-found 2>/dev/null'
    result = run_shell_tool(cmd, timeout=120)

    found = {}
    if os.path.exists(output_file):
        try:
            with open(output_file) as f:
                data = json.load(f)
                for site, info in data.items():
                    if info.get("status") == "Claimed":
                        found[site] = info.get("url_user", "")
            os.remove(output_file)
        except:
            pass

    return {"tool": "sherlock", "found_accounts": found, "count": len(found)}

def run_maigret(username, deep=False):
    """Run Maigret deep username investigation."""
    output_dir = f"/tmp/maigret_{username}_{int(time.time())}"
    cmd = f'maigret "{username}" --json --folderoutput "{output_dir}"'
    if deep:
        cmd += " --all-sites"

    result = run_shell_tool(cmd, timeout=300)

    found = {}
    report_file = os.path.join(output_dir, f"report_{username}.json")
    if os.path.exists(report_file):
        try:
            with open(report_file) as f:
                data = json.load(f)
                for site, info in data.items():
                    if info.get("status") == "Claimed":
                        found[site] = info
            # Cleanup
            import shutil
            shutil.rmtree(output_dir, ignore_errors=True)
        except:
            pass

    return {"tool": "maigret", "found_accounts": found, "count": len(found)}

def run_holehe(email):
    """Run Holehe email registration check."""
    cmd = f'holehe "{email}" --json 2>/dev/null'
    result = run_shell_tool(cmd, timeout=120)

    found = []
    try:
        # Parse holehe JSON output
        lines = result.get("stdout", "").strip().split("\n")
        for line in lines:
            if line.strip():
                try:
                    entry = json.loads(line)
                    if entry.get("exists"):
                        found.append({
                            "site": entry.get("name", ""),
                            "url": entry.get("url", ""),
                            "method": entry.get("method", "")
                        })
                except:
                    pass
    except:
        pass

    return {"tool": "holehe", "found_registrations": found, "count": len(found)}

def run_theharvester(domain):
    """Run theHarvester for domain recon."""
    output_file = f"/tmp/harvester_{domain}_{int(time.time())}"
    cmd = f'theHarvester -d "{domain}" -b all -f "{output_file}" 2>/dev/null'
    result = run_shell_tool(cmd, timeout=180)

    data = {"emails": [], "hosts": [], "ips": [], "asns": []}

    # Parse stdout for quick results
    stdout = result.get("stdout", "")
    for line in stdout.split("\n"):
        if "@" in line and "." in line and " " not in line.strip():
            data["emails"].append(line.strip())
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line.strip()):
            data["ips"].append(line.strip())

    # Try to parse XML output if exists
    xml_file = f"{output_file}.xml"
    if os.path.exists(xml_file):
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for email in root.findall(".//email"):
                if email.text:
                    data["emails"].append(email.text)
            for host in root.findall(".//host"):
                if host.text:
                    data["hosts"].append(host.text)
        except:
            pass

    return {"tool": "theharvester", "data": data}

def run_amass(domain):
    """Run Amass passive subdomain enumeration."""
    output_file = f"/tmp/amass_{domain}_{int(time.time())}.json"
    cmd = f'amass enum -passive -d "{domain}" -json "{output_file}" 2>/dev/null'
    result = run_shell_tool(cmd, timeout=300)

    subdomains = []
    if os.path.exists(output_file):
        try:
            with open(output_file) as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        name = entry.get("name", "")
                        if name:
                            subdomains.append(name)
            os.remove(output_file)
        except:
            pass

    return {"tool": "amass", "subdomains": list(set(subdomains)), "count": len(subdomains)}

def run_subfinder(domain):
    """Run Subfinder for fast subdomain discovery."""
    output_file = f"/tmp/subfinder_{domain}_{int(time.time())}.txt"
    cmd = f'subfinder -d "{domain}" -o "{output_file}" -silent 2>/dev/null'
    result = run_shell_tool(cmd, timeout=120)

    subdomains = []
    if os.path.exists(output_file):
        with open(output_file) as f:
            subdomains = [line.strip() for line in f if line.strip()]
        os.remove(output_file)

    return {"tool": "subfinder", "subdomains": subdomains, "count": len(subdomains)}

def run_httpx_probe(urls_list):
    """Probe URLs with httpx to find live hosts."""
    if not urls_list:
        return {"tool": "httpx", "live_hosts": []}

    input_file = f"/tmp/httpx_input_{int(time.time())}.txt"
    output_file = f"/tmp/httpx_output_{int(time.time())}.json"

    with open(input_file, "w") as f:
        f.write("\n".join(urls_list))

    cmd = f'httpx -l "{input_file}" -json -o "{output_file}" -silent 2>/dev/null'
    result = run_shell_tool(cmd, timeout=120)

    live = []
    if os.path.exists(output_file):
        try:
            with open(output_file) as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        live.append({
                            "url": entry.get("url", ""),
                            "status_code": entry.get("status_code", 0),
                            "title": entry.get("title", ""),
                            "tech": entry.get("technologies", []),
                            "server": entry.get("webserver", "")
                        })
            os.remove(output_file)
        except:
            pass

    if os.path.exists(input_file):
        os.remove(input_file)

    return {"tool": "httpx", "live_hosts": live, "count": len(live)}

def run_whois(domain):
    """Run WHOIS lookup."""
    cmd = f'whois "{domain}" 2>/dev/null'
    result = run_shell_tool(cmd, timeout=30)

    data = {}
    stdout = result.get("stdout", "")
    for line in stdout.split("\n"):
        if ":" in line:
            key, val = line.split(":", 1)
            data[key.strip().lower()] = val.strip()

    return {"tool": "whois", "data": data}

def run_dns_lookup(domain):
    """Run DNS lookups."""
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        cmd = f'dig +short {rtype} "{domain}" 2>/dev/null'
        result = run_shell_tool(cmd, timeout=15)
        lines = [l.strip() for l in result.get("stdout", "").split("\n") if l.strip()]
        if lines:
            records[rtype] = lines

    return {"tool": "dns", "records": records}

def run_nmap_quick(ip):
    """Run quick Nmap scan."""
    cmd = f'nmap -sV --top-ports 20 -T4 --open "{ip}" -oX - 2>/dev/null'
    result = run_shell_tool(cmd, timeout=120)

    ports = []
    stdout = result.get("stdout", "")
    # Simple XML parsing fallback
    for line in stdout.split("\n"):
        if 'portid="' in line and 'state="open"' in line:
            match = re.search(r'portid="(\d+)"', line)
            if match:
                ports.append(match.group(1))

    return {"tool": "nmap", "open_ports": ports}

def run_exiftool(file_path):
    """Run ExifTool on a file."""
    if not os.path.exists(file_path):
        return {"tool": "exiftool", "error": "File not found"}

    cmd = f'exiftool -json "{file_path}" 2>/dev/null'
    result = run_shell_tool(cmd, timeout=30)

    try:
        data = json.loads(result.get("stdout", "[]"))
        return {"tool": "exiftool", "metadata": data[0] if data else {}}
    except:
        return {"tool": "exiftool", "raw": result.get("stdout", "")}

# ============ API CALLERS ============

def call_api(name, config, target):
    """Call a free API endpoint."""
    result = {"api": name, "success": False, "data": None, "error": None}

    try:
        url = config["url"]
        headers = {"User-Agent": USER_AGENT}

        # Handle dynamic type for AlienVault OTX
        if config.get("dynamic_type"):
            target_type = "IPv4" if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target) else "domain"
            url = url.replace("{type}", target_type)

        # API key handling
        if config.get("needs_key"):
            key = os.environ.get(config.get("env_key", ""), "")
            if not key:
                result["error"] = f"API key missing: {config.get('env_key')}"
                return result
            url = url.replace("{key}", quote(key))

            # Custom headers with key substitution
            for hkey, hval in config.get("headers", {}).items():
                headers[hkey] = hval.replace("{key}", key)

        url = url.replace("{target}", quote(target))

        method = config.get("method", "GET")
        data = config.get("data")
        if data:
            data = {k: v.replace("{target}", target) for k, v in data.items()}

        # Auth handling
        auth = None
        if config.get("auth") == "basic":
            api_id = os.environ.get("CENSYS_API_ID", "")
            api_secret = os.environ.get("CENSYS_API_SECRET", "")
            if api_id and api_secret:
                auth = (api_id, api_secret)

        if method == "POST":
            resp = requests.post(url, headers=headers, data=data, timeout=TIMEOUT, auth=auth)
        else:
            resp = requests.get(url, headers=headers, timeout=TIMEOUT, auth=auth)

        if resp.status_code == 200:
            try:
                result["data"] = resp.json()
            except:
                result["data"] = {"raw": resp.text}
            result["success"] = True
        elif resp.status_code == 404:
            result["data"] = {"message": "No data found"}
            result["success"] = True
        else:
            result["error"] = f"HTTP {resp.status_code}"

    except requests.exceptions.Timeout:
        result["error"] = "Request timeout"
    except Exception as e:
        result["error"] = str(e)

    return result

# ============ PIPELINE ENGINE ============

def pipeline_email(email, deep=False):
    """Full email investigation pipeline."""
    print(f"[PIPELINE] Starting email investigation: {email}")
    report = {"target": email, "type": "email", "timestamp": datetime.now().isoformat(), "results": {}}

    # Step 1: Holehe (free, no API key)
    print("  -> Running Holehe (email registrations)...")
    report["results"]["holehe"] = run_holehe(email)

    # Step 2: Free APIs
    print("  -> Calling free APIs...")
    apis_to_call = [k for k, v in FREE_APIS.items() if "email" in v["type"]]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(call_api, name, FREE_APIS[name], email): name 
                   for name in apis_to_call}
        for future in as_completed(futures):
            name = futures[future]
            report["results"][name] = future.result()

    # Step 3: Extract usernames from email and search them
    username = email.split("@")[0]
    print(f"  -> Pivoting to username: {username}")
    report["results"]["pivoted_username"] = username
    report["results"]["sherlock"] = run_sherlock(username)

    if deep:
        print(f"  -> Running deep Maigret on {username}...")
        report["results"]["maigret"] = run_maigret(username, deep=True)

    # Step 4: Check domain
    domain = email.split("@")[1]
    print(f"  -> Checking domain: {domain}")
    report["results"]["domain_whois"] = run_whois(domain)
    report["results"]["domain_dns"] = run_dns_lookup(domain)

    return report

def pipeline_username(username, deep=False):
    """Full username investigation pipeline."""
    print(f"[PIPELINE] Starting username investigation: {username}")
    report = {"target": username, "type": "username", "timestamp": datetime.now().isoformat(), "results": {}}

    # Step 1: Sherlock (free, no API key)
    print("  -> Running Sherlock...")
    report["results"]["sherlock"] = run_sherlock(username)

    # Step 2: Maigret (free, no API key)
    print("  -> Running Maigret...")
    report["results"]["maigret"] = run_maigret(username, deep=deep)

    # Step 3: Free APIs
    print("  -> Calling free APIs...")
    apis_to_call = [k for k, v in FREE_APIS.items() if "username" in v["type"]]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(call_api, name, FREE_APIS[name], username): name 
                   for name in apis_to_call}
        for future in as_completed(futures):
            name = futures[future]
            report["results"][name] = future.result()

    # Step 4: GitHub profile
    print("  -> Checking GitHub...")
    report["results"]["github_user"] = call_api("github_user", FREE_APIS["github_user"], username)

    return report

def pipeline_domain(domain, deep=False):
    """Full domain investigation pipeline."""
    print(f"[PIPELINE] Starting domain investigation: {domain}")
    report = {"target": domain, "type": "domain", "timestamp": datetime.now().isoformat(), "results": {}}

    # Step 1: WHOIS + DNS
    print("  -> Running WHOIS and DNS...")
    report["results"]["whois"] = run_whois(domain)
    report["results"]["dns"] = run_dns_lookup(domain)

    # Step 2: Subdomain enumeration
    print("  -> Enumerating subdomains (Amass + Subfinder)...")
    report["results"]["amass"] = run_amass(domain)
    report["results"]["subfinder"] = run_subfinder(domain)

    # Merge subdomains
    all_subs = set()
    all_subs.update(report["results"]["amass"].get("subdomains", []))
    all_subs.update(report["results"]["subfinder"].get("subdomains", []))
    report["all_subdomains"] = sorted(list(all_subs))

    # Step 3: Probe live hosts
    if report["all_subdomains"]:
        urls = [f"http://{s}" for s in report["all_subdomains"][:100]]  # Limit to 100
        print(f"  -> Probing {len(urls)} hosts with httpx...")
        report["results"]["httpx"] = run_httpx_probe(urls)

    # Step 4: theHarvester
    print("  -> Running theHarvester...")
    report["results"]["theharvester"] = run_theharvester(domain)

    # Step 5: Free APIs
    print("  -> Calling free APIs...")
    apis_to_call = [k for k, v in FREE_APIS.items() if "domain" in v["type"]]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(call_api, name, FREE_APIS[name], domain): name 
                   for name in apis_to_call}
        for future in as_completed(futures):
            name = futures[future]
            report["results"][name] = future.result()

    # Step 6: Deep scan - Nmap top IPs
    if deep and report["results"]["dns"].get("records", {}).get("A"):
        ip = report["results"]["dns"]["records"]["A"][0]
        print(f"  -> Quick Nmap on {ip}...")
        report["results"]["nmap"] = run_nmap_quick(ip)

    return report

def pipeline_ip(ip, deep=False):
    """Full IP investigation pipeline."""
    print(f"[PIPELINE] Starting IP investigation: {ip}")
    report = {"target": ip, "type": "ip", "timestamp": datetime.now().isoformat(), "results": {}}

    # Step 1: Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        report["reverse_dns"] = hostname
    except:
        report["reverse_dns"] = None

    # Step 2: Free APIs
    print("  -> Calling free APIs...")
    apis_to_call = [k for k, v in FREE_APIS.items() if "ip" in v["type"]]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(call_api, name, FREE_APIS[name], ip): name 
                   for name in apis_to_call}
        for future in as_completed(futures):
            name = futures[future]
            report["results"][name] = future.result()

    # Step 3: Nmap quick scan
    if deep:
        print("  -> Running Nmap...")
        report["results"]["nmap"] = run_nmap_quick(ip)

    return report

def pipeline_phone(phone):
    """Phone number investigation pipeline."""
    print(f"[PIPELINE] Starting phone investigation: {phone}")
    report = {"target": phone, "type": "phone", "timestamp": datetime.now().isoformat(), "results": {}}

    # Free APIs
    apis_to_call = [k for k, v in FREE_APIS.items() if "phone" in v["type"]]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(call_api, name, FREE_APIS[name], phone): name 
                   for name in apis_to_call}
        for future in as_completed(futures):
            name = futures[future]
            report["results"][name] = future.result()

    return report

def pipeline_hash(hash_value):
    """Hash/malware investigation pipeline."""
    print(f"[PIPELINE] Starting hash investigation: {hash_value}")
    report = {"target": hash_value, "type": "hash", "timestamp": datetime.now().isoformat(), "results": {}}

    # Free APIs
    apis_to_call = [k for k, v in FREE_APIS.items() if "hash" in v["type"]]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(call_api, name, FREE_APIS[name], hash_value): name 
                   for name in apis_to_call}
        for future in as_completed(futures):
            name = futures[future]
            report["results"][name] = future.result()

    return report

# ============ REPORTING ============

def generate_summary(report):
    """Generate a human-readable summary."""
    target = report["target"]
    target_type = report["type"]

    summary = [f"\n{'='*60}", f"OSINT REPORT: {target} ({target_type.upper()})", f"{'='*60}"]

    if target_type == "email":
        holehe = report["results"].get("holehe", {})
        summary.append(f"\n[EMAIL REGISTRATIONS] {holehe.get('count', 0)} platforms found")
        for reg in holehe.get("found_registrations", [])[:10]:
            summary.append(f"  - {reg['site']}: {reg['url']}")

        sherlock = report["results"].get("sherlock", {})
        summary.append(f"\n[USERNAME PIVOT] {sherlock.get('count', 0)} accounts for '{target.split('@')[0]}'")

        hibp = report["results"].get("haveibeenpwned", {})
        if hibp.get("success"):
            breaches = hibp.get("data", [])
            summary.append(f"\n[BREACHES] Found in {len(breaches)} known breach(es)")
            for b in breaches[:5]:
                summary.append(f"  - {b.get('Name', 'Unknown')}: {b.get('BreachDate', 'N/A')}")

        emailrep = report["results"].get("emailrep", {})
        if emailrep.get("success"):
            data = emailrep.get("data", {})
            summary.append(f"\n[EMAIL REPUTATION] Rep: {data.get('reputation', 'N/A')}, Suspicious: {data.get('suspicious', 'N/A')}")

    elif target_type == "username":
        sherlock = report["results"].get("sherlock", {})
        summary.append(f"\n[SHERLOCK] {sherlock.get('count', 0)} accounts found")

        maigret = report["results"].get("maigret", {})
        summary.append(f"[MAIGRET] {maigret.get('count', 0)} accounts found")

        gh = report["results"].get("github_user", {})
        if gh.get("success"):
            data = gh.get("data", {})
            summary.append(f"\n[GITHUB] {data.get('name', target)} - {data.get('public_repos', 0)} repos, {data.get('followers', 0)} followers")

    elif target_type == "domain":
        subs = report.get("all_subdomains", [])
        summary.append(f"\n[SUBDOMAINS] {len(subs)} discovered")
        for s in subs[:15]:
            summary.append(f"  - {s}")

        harvester = report["results"].get("theharvester", {})
        emails = harvester.get("data", {}).get("emails", [])
        summary.append(f"\n[EMAILS] {len(emails)} found via theHarvester")
        for e in emails[:10]:
            summary.append(f"  - {e}")

        live = report["results"].get("httpx", {}).get("live_hosts", [])
        summary.append(f"\n[LIVE HOSTS] {len(live)} responding")
        for h in live[:10]:
            summary.append(f"  - {h['url']} [{h['status_code']}] {h['title'][:40]}")

    elif target_type == "ip":
        rev = report.get("reverse_dns")
        if rev:
            summary.append(f"\n[REVERSE DNS] {rev}")

        ipinfo = report["results"].get("ipinfo", {})
        if ipinfo.get("success"):
            data = ipinfo.get("data", {})
            summary.append(f"\n[GEOLOCATION] {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}")
            summary.append(f"[ORG] {data.get('org', 'N/A')}")

        abuse = report["results"].get("abuseipdb", {})
        if abuse.get("success"):
            data = abuse.get("data", {}).get("data", {})
            summary.append(f"\n[ABUSE SCORE] {data.get('abuseConfidencePercentage', 0)}%")

    summary.append(f"\n{'='*60}")
    return "\n".join(summary)

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Orchestrator - Pipeline engine for free OSINT tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 osint_orchestrator.py -t john@example.com -T email
  python3 osint_orchestrator.py -t johndoe -T username --deep
  python3 osint_orchestrator.py -t example.com -T domain --deep -o report.json
  python3 osint_orchestrator.py -t 8.8.8.8 -T ip
  python3 osint_orchestrator.py -t +14155552671 -T phone
  python3 osint_orchestrator.py -t 44d88612fea8a8f36de82e1278abb02f -T hash
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target to investigate")
    parser.add_argument("-T", "--type", required=True, 
                        choices=["email", "username", "domain", "ip", "phone", "hash"],
                        help="Type of target")
    parser.add_argument("--deep", action="store_true", help="Enable deep scan (slower, more thorough)")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("--summary-only", action="store_true", help="Print only summary, skip JSON")

    args = parser.parse_args()

    # Route to correct pipeline
    pipelines = {
        "email": pipeline_email,
        "username": pipeline_username,
        "domain": pipeline_domain,
        "ip": pipeline_ip,
        "phone": pipeline_phone,
        "hash": pipeline_hash,
    }

    pipeline_fn = pipelines[args.type]
    report = pipeline_fn(args.target, deep=args.deep)

    # Generate summary
    summary = generate_summary(report)
    print(summary)

    # Save JSON
    if not args.summary_only:
        if args.output:
            output_path = args.output
        else:
            safe_target = re.sub(r"[^\w\-\.]", "_", args.target)
            output_path = f"osint_report_{args.type}_{safe_target}_{int(time.time())}.json"

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n[SAVE] Full report saved to: {output_path}")
        print(f"[SIZE] {os.path.getsize(output_path)} bytes")

if __name__ == "__main__":
    # DEPRECATED & QUARANTINED: this standalone script predates the package and duplicates
    # bunnyhole.agents.osint, but it runs external tools via subprocess with shell=True and
    # f-string-interpolated targets (shell-injection risk), parses the vault incorrectly, and can
    # leak API keys into report/error text. Do NOT use it. It is retained only for reference and is
    # scheduled for removal; run `bunnyhole trace <seed>` instead. Set BUNNYHOLE_ALLOW_LEGACY=1 to
    # override this guard at your own risk.
    import sys as _sys

    if os.environ.get("BUNNYHOLE_ALLOW_LEGACY") != "1":
        print(
            "[DEPRECATED] scripts/osint_orchestrator.py is quarantined for security reasons "
            "(shell-injection risk). Use the maintained engine: `bunnyhole trace <seed>`.\n"
            "Set BUNNYHOLE_ALLOW_LEGACY=1 to run it anyway (not recommended).",
            file=_sys.stderr,
        )
        _sys.exit(2)
    main()
