# ----- License -------------------------------------------------- # 

#  EndScan - EndScan enumerates candidate cloud resources, Microsoft tenant metadata, 
#  DNS assets, and potential GitHub secret exposures, consolidating observations into JSON reports.
#  Copyright (c) 2026 - CursedSec (Operated by Cursed271). All rights reserved.

#  This software is an proprietary intellectual property developed for
#  penetration testing, threat modeling, and security research. It   
#  is licensed under the CURSEDSEC OWNERSHIP EDICT:
#
#  🚫 PROHIBITION WARNING 🚫
#  Redistribution, re-uploading, and unauthorized modification are strictly forbidden 
#  under the COE. Use is granted ONLY under the limited terms defined in the official 
#  LICENSE file (COE), which must be included in all copies.

#  DISCLAIMER:
#  This tool is intended for **educational or ethical testing** purposes only.
#  Unauthorized or malicious use of this software against systems without 
#  proper authorization is strictly prohibited and may violate laws and regulations.
#  The author assumes no liability for misuse or damage caused by this tool.

#  🔗 LICENSE: CURSEDSEC OWNERSHIP EDICT (COE)
#  🔗 Repository: https://github.com/Cursed271
#  🔗 Author: Steven Pereira (@Cursed271)

# ----- Libraries ------------------------------------------------ #

import re
import os
import json
import click
import typer
import urllib3
import requests
from pathlib import Path
from rich.rule import Rule
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.console import Console
import typer.rich_utils as typer_rich
from typing import Any, Dict, List, Optional

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ----- Global Declaration --------------------------------------- #

console = Console()
app = typer.Typer(add_completion = False, context_settings = {"help_option_names": ["-h", "--help"]})
OFFICE_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----- AWS Enumeration ------------------------------------------ #

def aws_sanitize(name:str) -> Optional[str]:
    if not name:
        return None
    name = name.lower()
    name = name.replace("_", "-").replace(".", "-")
    name = re.sub(r"-+", "-", name)
    name = name.strip("-")
    if len(name) < 3 or len(name) > 63:
        return None
    if not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$", name):
        return None
    return name

def aws_enumerate(domain:str, session: requests.Session, wordlist: Optional[List[str]] = None) -> Dict[str, List[str]]:
    base_names = [
        domain.lower(),
        domain.replace(".", "").lower(),
        domain.replace(".", "-").lower(),
        domain.split(".")[0].lower(), 
    ]
    suffixes = [
        "", "-prod", "-dev", "-staging", "-backup", "-assets", 
        "-static", "-media", "-logs", "-data", "-storage", "-public",
        "-archive", "-files", "uploads", "-content"
    ]
    prefixes = ["", "aws-", "amazon-", "cloud-", "app-", "web-"]
    bucket_candidates = set()
    for base in base_names:
        for prefix in prefixes: 
            for suffix in suffixes:
                candidate = f"{prefix}{base}{suffix}"
                sanitized = aws_sanitize(candidate)
                if sanitized:
                    bucket_candidates.add(sanitized)
    if wordlist:
        for word in wordlist:
            sanitized = aws_sanitize(word)
            if sanitized:
                bucket_candidates.add(sanitized)
    results = {
        "public": [],
        "private": [],
        "redirect": []
    }
    for bucket in bucket_candidates:
        url = f"https://{bucket}.s3.amazonaws.com/"
        try:
            resp = session.get(url, timeout = 5, verify = False)
            if resp.status_code == 200:
                results["public"].append(bucket)
            elif resp.status_code == 403:
                results["private"].append(bucket)
            elif resp.status_code == 301:
                results["redirect"].append(bucket)
        except requests.exceptions.RequestException:
            continue
    return results

def aws_checkID(domain: str, session: requests.Session) -> List[str]:
    endpoints = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/robots.txt",
        f"https://{domain}",
    ]
    discovered_ids = []
    arn_pattern = r"arn:aws:[a-z0-9\-]+::(\d{12}):"
    for url in endpoints:
        try:
            resp = session.get(url, timeout = 5, verify = False)
            if resp.status_code == 200:
                matches = re.findall(arn_pattern, resp.text)
                for acc_id in matches:
                    if acc_id not in discovered_ids:
                        discovered_ids.append(acc_id)
        except requests.exceptions.RequestException:
            continue
    return discovered_ids

# ----- Microsoft/Azure Enumeration ------------------------------ #

def azure_tenant(domain: str, session: requests.Session) -> Dict[str, Any]:
    tenant_info: Dict[str, Any] = {
        "tenant_id": None, 
        "branding_login_url": None, 
        "namespace_type": "Unknown",
        "domain_type": "Unknown",
        "federation_brand": None,
        "endpoints": {}
    }
    openid_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
    try:
        resp = session.get(openid_url, timeout = 10)
        if resp.status_code == 200:
            data = resp.json()
            token_endpoint = data.get("token_endpoint", "")
            guid_pattern = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
            match = re.search(guid_pattern, token_endpoint)
            if match:
                tenant_id = match.group(0)
                tenant_info["tenant_id"] = tenant_id
                tenant_info["branding_login_url"] = (
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/authorize"
                    f"?client_id={OFFICE_CLIENT_ID}&response_type=code"
                )
            tenant_info["endpoints"]["authorization"] = data.get("authorization_endpoint")
            tenant_info["endpoints"]["token"] = token_endpoint
    except requests.exceptions.RequestException:
        pass
    realm_url = f"https://login.microsoftonline.com/getuserrealm.srf?login=test@{domain}&json=1"
    try:
        resp = session.get(realm_url, timeout = 10)
        if resp.status_code == 200:
            realm_data = resp.json()
            tenant_info["namespace_type"] = realm_data.get("NameSpaceType", "Unknown")
            tenant_info["domain_type"] = realm_data.get("DomainType", "Unknown")
            tenant_info["federation_brand"] = realm_data.get("FederationBrandName")
    except requests.exceptions.RequestException:
        pass
    cred_url = "https://login.microsoftonline.com/common/GetCredentialType"
    try:
        payload = {"username": f"admin@{domain}"}
        resp = session.post(cred_url, json = payload, timeout = 10)
        if resp.status_code == 200:
            tenant_info["credential_type_accessible"] = True
    except requests.exceptions.RequestException:
        tenant_info["credential_type_accessible"] = False
    return tenant_info

def azure_enumerate(target_name: str, session: requests.Session, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    slug = target_name.lower().split(".")[0]
    patterns = [
        f"{slug}.blob.core.windows.net",
        f"{slug}.file.core.windows.net",
        f"{slug}.queue.core.windows.net",
        f"{slug}.table.core.windows.net",
        f"{slug}.azurewebsites.net",
        f"{slug}.cloudapp.net",
        f"{slug}.cloudapp.azure.com",
        f"{slug}.azure-api.net",
        f"{slug}.database.windows.net",
        f"{slug}.redis.cache.windows.net",
        f"{slug}.servicebus.windows.net",
        f"{slug}.vault.azure.net",
        f"{slug}.b2clogin.com",
        f"{slug}.azurefd.net",        
    ]
    if tenant_id:
        short_id = tenant_id.replace("-", "")
        patterns.extend([
            f"{tenant_id}.vault.azure.net",
            f"{short_id}.blob.core.windows.net",
        ])
    discovered_endpoints: List[Dict[str, Any]] = []
    for endpoint in patterns:
        url = f"https://{endpoint}"
        try:
            resp = session.head(url, timeout = 5, allow_redirects = True, verify = False)
            if resp.status_code in (200, 301, 302, 403):
                discovered_endpoints.append({
                    "endpoint": endpoint,
                    "url": url,
                    "status_code": resp.status_code
                })
        except requests.exceptions.RequestException:
            continue
    return discovered_endpoints

# ----- Github Enumeration --------------------------------------- #

def github_info(org_name: str, session: requests.Session) -> Optional[Dict[str, Any]]:
    org_url = f"https://api.github.com/orgs/{org_name}"
    try:
        resp = session.get(org_url, timeout = 10)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return None
        elif resp.status_code == 403:
            return {"rate_limited": True}
    except requests.exceptions.RequestException:
        pass
    return None

def github_repos(org_name: str, session: requests.Session) -> List[Dict[str, Any]]:
    all_repos: List[Dict[str, Any]] = []
    page = 1
    per_page = 100
    repos_url = f"https://api.github.com/orgs/{org_name}/repos"
    while True:
        params = {"per_page": per_page, "page": page, "type": "all"}
        try:
            resp = session.get(repos_url, params = params, timeout = 10)
            if resp.status_code != 200:
                break
            repos = resp.json()
            if not repos:
                break
            for repo in repos:
                all_repos.append({
                    "name": repo.get("name"),
                    "full_name": repo.get("full_name"),
                    "html_url": repo.get("html_url"),
                    "language": repo.get("language"),
                    "stars": repo.get("stargazers_count", 0),
                    "forks": repo.get("forks_count", 0),
                    "is_private": repo.get("private", False),
                    "created_at": repo.get("created_at"),
                    "updated_at": repo.get("updated_at"),
                })
            if "next" not in resp.links:
                break
            page += 1
        except requests.exceptions.RequestException:
            break
    return all_repos

def github_secrets(org_name: str, repo_name: str, session: requests.Session) -> List[Dict[str, Any]]:
    files_to_check = [
        "README.md", "config.json", "settings.json", ".env.example",
        ".env", "docker-compose.yml", "package.json",
    ]
    secret_patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "Generic API Key": r"api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{20,}",
        "Password in Config": r"password['\"]?\s*[:=]\s*['\"][^'\"]{8,}",
        "Private Key Header": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    }
    findings: List[Dict[str, Any]] = []
    for file_name in files_to_check:
        for branch in ("main", "master"):
            raw_url = f"https://raw.githubusercontent.com/{org_name}/{repo_name}/{branch}/{file_name}"
            try: 
                resp = session.get(raw_url, timeout = 5, verify = False)
                if resp.status_code == 200:
                    content = resp.text
                    for secret_type, regex_pattern in secret_patterns.items():
                        matches = re.findall(regex_pattern, content, re.IGNORECASE)
                        if matches:
                            findings.append({
                                "repo": repo_name,
                                "file": file_name,
                                "branch": branch,
                                "secret_type": secret_type,
                                "raw_url": raw_url,
                                "match_count": len(matches)
                            })
            except requests.exceptions.RequestException:
                continue
    return findings

# ----- DNS/SubDomain Enumeration -------------------------------- #

def subdomain_anubis(domain: str, session: requests.Session) -> List[str]:
    url = f"https://anubisdb.com/subdomains/{domain}"
    discovered = set()
    try:
        resp = session.get(url, timeout = 10)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for hostname in data:
                    hostname = str(hostname).strip().lower()
                    if hostname.endswith(domain) and hostname != domain:
                        discovered.add(hostname)
    except requests.exceptions.RequestException:
        pass
    return list(discovered)

def subdomain_hackertarget(domain: str, session: requests.Session) -> List[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    discovered = set()
    try:
        resp = session.get(url, timeout = 10)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                if "," in line:
                    hostname = line.split(",")[0].strip().lower()
                    if hostname.endswith(domain) and hostname != domain:
                        discovered.add(hostname)
    except requests.exceptions.RequestException:
        pass
    return list(discovered)

def dns_subdomains(domain: str, session: requests.Session, wordlist: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    candidates = set(subdomain_anubis(domain, session))
    candidates.update(subdomain_hackertarget(domain, session))
    if wordlist:
        for word in wordlist:
            word = word.strip().lower()
            if word:
                candidates.add(f"{word}.{domain}" if not word.endswith(domain) else word)
    live_subdomains: List[Dict[str, Any]] = []
    if DNS_AVAILABLE and candidates:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 2.5
        for sub in sorted(candidates):
            try:
                answers = resolver.resolve(sub, "A")
                ips = [str(rdata) for rdata in answers]
                if ips:
                    live_subdomains.append({
                        "subdomain": sub,
                        "ip_addresses": ips
                    })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
                continue
    else:
        live_subdomains = [{"subdomain": sub, "ip_addresses": ["Unresolved"]} for sub in sorted(candidates)]
    return live_subdomains

def dns_nameservers(domain: str) -> Dict[str, Any]:
    if not DNS_AVAILABLE:
        return {"nameservers": [], "is_route53": False, "provider": "Unknown"}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0
    try:
        answers = resolver.resolve(domain, "NS")
        ns_records = [str(rdata).rstrip(".") for rdata in answers]
        is_route53 = any("awsdns" in ns.lower() or "route53" in ns.lower() for ns in ns_records)
        provider = "AWS Route53" if is_route53 else "External/On-Prem"
        return {
            "nameservers": ns_records,
            "is_route53": is_route53,
            "provider": provider
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
        return {"nameservers": [], "is_route53": False, "provider": "Resolution Failed"}

# ----- Other Cloud Enumeration ---------------------------------- #

def cloud_storage(domain: str, session: requests.Session) -> List[Dict[str, Any]]:
    slug = domain.lower().split(".")[0]
    clean_domain = domain.lower().strip()
    endpoints = {
        "Google Cloud Storage": [
            f"https://storage.googleapis.com/{clean_domain}",
            f"https://{clean_domain}.storage.googleapis.com",
            f"https://storage.googleapis.com/{slug}",
            f"https://{slug}.storage.googleapis.com",
        ],
        "DigitalOcean Spaces": [
            f"https://{clean_domain}.nyc3.digitaloceanspaces.com",
            f"https://{clean_domain}.sfo3.digitaloceanspaces.com",
            f"https://{clean_domain}.ams3.digitaloceanspaces.com",
            f"https://{slug}.nyc3.digitaloceanspaces.com",
            f"https://{slug}.sfo3.digitaloceanspaces.com",
            f"https://{slug}.ams3.digitaloceanspaces.com",
        ],
    }
    discovered: List[Dict[str, Any]] = []
    for provider, urls in endpoints.items():
        for url in urls:
            try:
                resp = session.head(url, timeout = 5, allow_redirects = True, verify = False)
                if resp.status_code in (200, 301, 302, 403):
                    is_public = resp.status_code == 200
                    discovered.append({
                        "provider": provider,
                        "url": url,
                        "status_code": resp.status_code,
                        "public": is_public,
                        "state": "Publicly Accessible" if is_public else "Protected / Exists",
                    })
            except requests.exceptions.RequestException:
                continue
    return discovered

# ----- Summary Table -------------------------------------------- #

def summary_table(domain, report: Dict[str, Any]) -> None:
    title_domain = domain.split(".")[0].title()
    table = Table(
        title = f"[bold white]EndScan - Reconnaissance Findings Summary for {title_domain}[/bold white]",
        border_style = "#C6ECE3",
        header_style = "#C6ECE3",
        expand = False
    )
    table.add_column("Category", style = "bold white", justify = "left")
    table.add_column("Assets Identified", style = "#C6ECE3", justify = "left")
    table.add_column("Status", style = "#C6ECE3", justify = "left")
    pub_s3 = len(report["aws"]["buckets"]["public"])
    priv_s3 = len(report["aws"]["buckets"]["private"])
    table.add_row(
        "AWS S3 Buckets",
        str(pub_s3 + priv_s3),
        f"[bold #FF6B6B]{pub_s3} Public[/bold #FF6B6B] | [dim]{priv_s3} Private[/dim]" if pub_s3 else f"{priv_s3} Private"
    )
    table.add_row("AWS Account IDs", str(len(report["aws"]["account_ids"])), "ARN Metadata Extracted")
    tenant_status = "Resolved" if report["azure"]["tenant"].get("tenant_id") else "Not Detected"
    table.add_row("Azure AD Tenant", tenant_status, report["azure"]["tenant"].get("tenant_id") or "N/A")
    table.add_row("Azure Endpoints", str(len(report["azure"]["subdomains"])), "Active Service FQDNs")
    repo_count = len(report["github"]["repositories"])
    secrets_count = sum(len(r.get("secrets", [])) for r in report["github"]["repositories"])
    table.add_row(
        "GitHub Repositories", 
        str(repo_count), 
        "Publicly Visible" if repo_count else "None Found"
    )
    table.add_row(
        "GitHub Exposed Secrets", 
        f"[bold #FF6B6B]{secrets_count}[/bold #FF6B6B]" if secrets_count else "0", 
        f"[bold #FF6B6B]{secrets_count} Critical Leaks Found[/bold #FF6B6B]" if secrets_count else "[green]Clean / No Secrets Found[/green]"
    )
    sub_count = len(report["dns"]["subdomains"])
    ns_provider = report["dns"]["nameservers"].get("provider", "Unknown")
    table.add_row("Active Subdomains", str(sub_count), f"Nameservers: {ns_provider}")
    ext_storage = len(report["cloud_storage"])
    table.add_row("Other Cloud Storage", str(ext_storage), "GCS & DigitalOcean Containers")
    console.print()
    console.print(table)
    console.print()

# ----- Orchestration -------------------------------------------- #

def orchestrate(domain: str, org: Optional[str] = None, token: Optional[str] = None, wordlist: Optional[List[str]] = None, output: Optional[str] = None) -> Dict[str, Any]:
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    })
    if token:
        session.headers.update({"Authorization": f"token {token}"})
    org_target = org if org else domain.split(".")[0]
    report: Dict[str, Any] = {
        "target": domain,
        "github_target": org_target,
        "aws": {"buckets": {"public": [], "private": [], "redirect": []}, "account_ids": []},
        "azure": {"tenant": {}, "subdomains": []},
        "github": {"org_info": {}, "repositories": []},
        "dns": {"nameservers": {}, "subdomains": []},
        "cloud_storage": [],
    }
    with console.status(f"[#BB9AF7][!] Scanning AWS S3 Buckets and Account IDs...", spinner = "dots"):
        report["aws"]["buckets"] = aws_enumerate(domain, session, wordlist = wordlist)
        report["aws"]["account_ids"] = aws_checkID(domain, session)
    console.print(f"[#2ECC71][+] AWS Enumeration has been completed successfully!")
    with console.status(f"[#BB9AF7][!] Querying Microsoft Entra/Azure AD...", spinner = "dots"):
        tenant_info = azure_tenant(domain, session)
        report["azure"]["tenant"] = tenant_info
        report["azure"]["subdomains"] = azure_enumerate(domain, session, tenant_id = tenant_info.get("tenant_id"))
    console.print(f"[#2ECC71][+] Azure Enumeration has been completed successfully!")
    with console.status(f"[#BB9AF7][!] Scanning GitHub Repositories...", spinner = "dots"):
        report["github"]["org_info"] = github_info(org_target, session)
        repos = github_repos(org_target, session)
        for repo in repos:
            repo["secrets"] = github_secrets(org_target, repo["name"], session)
            report["github"]["repositories"] = repos
    console.print(f"[#2ECC71][+] GitHub Enumeration has been completed successfully!")
    with console.status(f"[#BB9AF7][!] Querying DNS Records and other Subdomains...", spinner = "dots"):
        report["dns"]["nameservers"] = dns_nameservers(domain)
        report["dns"]["subdomains"] = dns_subdomains(domain, session, wordlist = wordlist)
    console.print(f"[#2ECC71][+] Subdomain Enumeration has been completed successfully!")
    with console.status(f"[#BB9AF7][!] Probing Google Cloud and DigitalOcean Endpoints...", spinner = "dots"):
        report["cloud_storage"] = cloud_storage(domain, session)
    console.print(f"[#2ECC71][+] Multi-Cloud Enumeration has been completed successfully!")
    summary_table(domain, report)
    if output:
        if utils(report, output):
            console.print(f"[#2ECC71][+] JSON Report successfully written to [#BB9AF7]{output}[#BB9AF7]")
    return report

# ----- Utilities ------------------------------------------------ #

def utils(data: Dict[str, Any], filepath: str) -> bool:
    try:
        path = Path(filepath)
        path.parent.mkdir(parents = True, exist_ok = True)
        path.write_text(json.dumps(data, indent = 2))
        return True
    except Exception:
        console.print(f"[bold #FF6B6B][!] EndScan encountered an Error while saving the JSON Report [/bold #FF6B6B]")
        return False

# ----- ASCII Banner --------------------------------------------- #

def ascii() -> None:
    art_content = r"""
oooooooooooo                   .o8   .oooooo..o                                 
`888'     `8                  "888  d8P'    `Y8                                 
 888         ooo. .oo.    .oooo888  Y88bo.       .ooooo.   .oooo.   ooo. .oo.   
 888oooo8    `888P"Y88b  d88' `888   `"Y8888o.  d88' `"Y8 `P  )88b  `888P"Y88b  
 888    "     888   888  888   888       `"Y88b 888        .oP"888   888   888  
 888       o  888   888  888   888  oo     .d8P 888   .o8 d8(  888   888   888  
o888ooooood8 o888o o888o `Y8bod88P" 8""88888P'  `Y8bod8P' `Y888""8o o888o o888o 
"""
    art_color = Text(art_content, style = "#C6ECE3")
    art_panel = Panel(art_color, border_style = "#C6ECE3", expand = False)
    console.print(art_panel)
    banner_width = console.measure(art_panel).maximum
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print(f"  [~] Created by [bold red blink]Cursed271[/bold red blink]")
    console.print(f"  [~] EndScan - Trace the cloud. Connect the exposure.")
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print()
    return banner_width

# ----- Argument Parser ------------------------------------------ #

@app.command()
def argu(
    domain: str = typer.Option(None, "--domain", "-d", help = "Enter the Target Domain to inspect"),
    org: str = typer.Option(None, "--github", "-g", help = "Enter the Github Organization of the Target"),
    token: str = typer.Option(None, "--token", "-t", help = "Enter the your Personal Github Access Token", hide_input = True),
    wordlist: str = typer.Option(None, "--wordlist", "-w", help = "Enter the path to the Custom Wordlist"),
    output: str = typer.Option(None, "--output", "-o", help = "Enter the save path for the JSON export"),
) -> None:
    if not domain:
        domain = Prompt.ask(f"[#C6ECE3][?] Enter the Target Domain to inspect")
    if org is None:
        org_input = Prompt.ask(f"[#C6ECE3][?] Enter the Github Organization of the Target (Press Enter to Skip)")
        org = org_input if org_input else None
    clean_domain = domain.strip().lower()
    title_domain = domain.split(".")[0].title()
    clean_org = org.strip() if org else None
    clean_token = token.strip() if token else None
    clean_output = output.strip() if output else None
    loaded_words = []
    loaded_words = []
    if wordlist and wordlist.strip():
        wl_path = Path(wordlist.strip())
        if wl_path.is_file():
            loaded_words = [line.strip() for line in wl_path.read_text().splitlines() if line.strip()]
            console.print(f"[#2ECC71][+] Loaded {len(loaded_words)} from {wl_path.name}...")
        else:
            console.print(f"[bold #FFB86C][!] Wordlist file {wordlist.strip()} not found. Continuing with Passive Recon...")
    console.print(f"[#2ECC71][+] EndScan initiated a scan against [bold white]{title_domain}[/bold white]")
    orchestrate(domain = clean_domain, org = clean_org, token = clean_token, wordlist = loaded_words, output = clean_output)

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    banner_width = ascii()
    typer_rich.MAX_WIDTH = banner_width
    app()

# ----- End ------------------------------------------------------ #