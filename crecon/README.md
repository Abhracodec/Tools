# crecon

Automated recon toolkit for Kali Linux. One command. Full recon. AI-powered attack paths.

## What It Does

Chains everything together automatically based on what it finds:

- **Port scan** → open port 80? auto-triggers directory brute-forcing
- **Port scan** → open port 22? auto-tests default SSH credentials  
- **Web crawl** → extracts emails, phones, tech stack
- **Nuclei** → validates CVEs against discovered services
- **AI analysis** → builds complete attack chains from all findings

## Install
```bash
git clone https://github.com/Abhracodec/Tools.git
cd Tools/crecon
pip3 install -r requirements.txt --break-system-packages
pip3 install -e . --break-system-packages
sudo apt install nmap nuclei
```

> Tested on Kali Linux with Python 3.13.

## Setup AI (one time)
```bash
# free options
crecon config --add-key gsk_xxxx     --provider groq      # console.groq.com
crecon config --add-key AIzaxxxx     --provider gemini    # aistudio.google.com
crecon config --add-key ghp_xxxx     --provider github    # github.com/marketplace/models

# paid options  
crecon config --add-key sk-xxxx      --provider openai
crecon config --add-key sk-ant-xxxx  --provider anthropic
```

Auto-switches to next key if one runs out of credits.

## Usage
```bash
# full auto recon + AI attack chains
crecon auto <target> --ports 1-1024 --wordlist /usr/share/wordlists/dirb/common.txt --ai

# port scan only
crecon scan <target> --start 1 --end 1000 --banners --ai

# web recon + contact extraction
crecon recon --url https://target.com --output results.csv --ai

# directory brute-force
crecon enum dirs --url http://target.com --wordlist /usr/share/wordlists/dirb/common.txt --ai

# subdomain enumeration
crecon enum subs --domain target.com --wordlist /usr/share/wordlists/dnsmap.txt --ai

# manage API keys
crecon config --list-keys
crecon config --remove-key 1
```

## AI Providers Supported

| Provider | Cost | Model |
|----------|------|-------|
| Groq | Free | Llama 3.3 70B |
| Gemini | Free | Gemini 1.5 Flash |
| GitHub Models | Free (students) | GPT-4o |
| OpenAI | Paid | GPT-4o Mini |
| Anthropic | Paid | Claude Haiku |

## Requirements

- Kali Linux (or any Debian-based distro)
- Python 3.10+
- Nmap (`sudo apt install nmap`)
- Nuclei (`sudo apt install nuclei`)

## Legal

For authorized testing and educational use only.