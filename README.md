# crecon

Automated recon toolkit for Kali Linux. One command. Full recon. AI-powered attack paths.

## What It Does

Chains everything together automatically based on what it finds:

- **Port scan** → open port 80? auto-triggers directory brute-forcing
- **Port scan** → open port 22? auto-tests default SSH credentials
- **CVE lookup** → automatically queries NVD for every detected service version
- **Nuclei** → validates CVEs against discovered services
- **Web crawl** → extracts emails, phones, tech stack
- **AI analysis** → builds complete attack chains from all findings

## What Makes It Different

Most recon tools make you run everything manually. crecon chains them automatically — port scan triggers dir enum, web crawl, SSH testing, CVE lookup, and Nuclei validation without any extra commands. Then feeds everything to AI for actual attack paths, not just a summary.

Supports 5 AI providers with automatic fallback if one runs out of credits:

| Provider | Cost | Model |
|----------|------|-------|
| GitHub Models | Free (student) | DeepSeek-R1-0528 |
| Groq | Free | Llama 3.3 70B |
| Gemini | Free | Gemini 1.5 Flash |
| OpenAI | Paid | GPT-4o Mini |
| Anthropic | Paid | Claude Haiku |

## Install
```bash
git clone https://github.com/Abhracodec/Tools.git
cd Tools/crecon
pip3 install -r requirements.txt --break-system-packages
pip3 install -e . --break-system-packages
sudo apt install nmap nuclei
```

> Tested on Kali Linux with Python 3.13. The `--break-system-packages` flag is required on modern Kali due to PEP 668.

## Setup AI (one time)
```bash
# free options
crecon config --add-key github_pat_xxx  --provider github    # github.com/marketplace/models
crecon config --add-key gsk_xxxx        --provider groq      # console.groq.com
crecon config --add-key AIzaxxxx        --provider gemini    # aistudio.google.com

# paid options
crecon config --add-key sk-xxxx         --provider openai
crecon config --add-key sk-ant-xxxx     --provider anthropic

# check saved keys
crecon config --list-keys
```

Auto-switches to next key if one runs out of credits.

## Usage
```bash
# full auto recon + AI attack chains
crecon auto <target> --ports 1-1024 --wordlist /usr/share/wordlists/dirb/common.txt --ai

# port scan + CVE lookup + AI
crecon scan <target> --start 1 --end 1000 --banners --ai

# web recon + contact extraction
crecon recon --url https://target.com --output results.csv --ai

# directory brute-force
crecon enum dirs --url http://target.com --wordlist /usr/share/wordlists/dirb/common.txt --ai

# subdomain enumeration
crecon enum subs --domain target.com --wordlist /usr/share/wordlists/dnsmap.txt --ai
```

## How The Chain Works
```
crecon auto target
    │
    ├── Nmap scan (ports, versions, banners)
    │       └── NVD CVE lookup (automatic, no flag needed)
    │
    ├── Port 80/443 found
    │       ├── Directory brute-force (enumerator)
    │       ├── Web crawl (emails, phones, tech stack)
    │       └── Nuclei CVE validation
    │
    ├── Port 22 found
    │       └── SSH credential testing (paramiko)
    │
    └── AI analysis (DeepSeek-R1 / GPT-4o)
            └── Full attack chain with exact commands
```

## Requirements

- Kali Linux (or any Debian-based distro)
- Python 3.10+
- Nmap (`sudo apt install nmap`)
- Nuclei (`sudo apt install nuclei`)

## Legal

For authorized testing and educational use only. Only scan systems you have explicit permission to test.