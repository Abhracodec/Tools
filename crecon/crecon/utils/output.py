from colorama import Fore, Style, init as colorama_init
colorama_init(autoreset=True)

W  = Fore.WHITE
C  = Fore.CYAN
G  = Fore.GREEN
Y  = Fore.YELLOW
R  = Fore.RED
DG = Fore.LIGHTBLACK_EX   # dark grey
B  = Style.BRIGHT
D  = Style.RESET_ALL


BANNER = f"""
{DG}{'─' * 58}{D}
{B}{C}                                                        {D}
{B}{C}    ██████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗  {D}
{B}{C}   ██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗ ██║  {D}
{B}{C}   ██║     ██████╔╝█████╗  ██║     ██║  ██║██╔██╗██║  {D}
{B}{C}   ██║     ██╔══██╗██╔══╝  ██║     ██║  ██║██║╚████║  {D}
{B}{C}   ╚██████╗██║  ██║███████╗╚██████╗██████╔╝██║ ╚███║  {D}
{B}{C}    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═════╝ ╚═╝  ╚══╝  {D}
{B}{C}                                                        {D}
{DG}  Automated Recon Toolkit                    v0.1.0       {D}
{DG}  {'─' * 54}{D}
{DG}  github {W}https://github.com/Abhracodec{DG}                    {D}
{DG}{'─' * 58}{D}
"""


def banner():
    print(BANNER)


def phase(name):
    labels = {
        "nmap":  f"{B}{C}[NMAP]{D}",
        "enum":  f"{B}{Y}[ENUM]{D}",
        "recon": f"{B}{W}[RECON]{D}",
        "ssh":   f"{B}{R}[SSH]{D}",
    }
    label = labels.get(name, f"[{name.upper()}]")
    return label


def info(msg):
    print(f"  {DG}│{D}  {msg}")


def success(msg):
    print(f"  {G}✓{D}  {msg}")


def warn(msg):
    print(f"  {Y}!{D}  {msg}")


def error(msg):
    print(f"  {R}✗{D}  {msg}")


def finding(label, value, color=G):
    print(f"  {color}{B}{label:<14}{D}  {value}")


def section(title):
    print(f"\n  {DG}┌{'─' * 40}┐{D}")
    print(f"  {DG}│{D}  {B}{W}{title:<38}{D}  {DG}│{D}")
    print(f"  {DG}└{'─' * 40}┘{D}")


def port_line(port, service, product="", version=""):
    ver   = f"{product} {version}".strip()
    color = G if port in (22, 80, 443) else Y
    print(f"  {color}{B}{port:<7}{D}{DG}/{D}tcp   {W}{service:<14}{D}{DG}{ver}{D}")


def summary(report):
    hosts      = report.get("hosts", [])
    dirs       = report.get("dirs", [])
    recon_data = report.get("recon", [])
    ssh_hits   = report.get("ssh_hits", [])

    all_emails = set()
    all_phones = set()
    all_tech   = []

    for page in recon_data:
        all_emails.update(page.get("emails", []))
        all_phones.update(page.get("phones", []))
        all_tech.extend(page.get("tech", []))

    open_count = sum(len(h["ports"]) for h in hosts)

    section("Scan Summary")
    finding("Hosts up",    len(hosts))
    finding("Open ports",  open_count)
    finding("Dirs found",  len(dirs))
    finding("Emails",      len(all_emails))
    finding("Phones",      len(all_phones))
    finding("SSH hits",    len(ssh_hits), color=R if ssh_hits else G)

    tech_list = list(dict.fromkeys(all_tech))
    if tech_list:
        finding("Tech",    ", ".join(tech_list), color=C)

    if all_emails:
        section("Emails Found")
        for e in sorted(all_emails):
            info(e)

    if ssh_hits:
        section("Valid SSH Credentials")
        for h in ssh_hits:
            success(f"{h['username']}:{h['password']}  →  {h['host']}:{h['port']}")

    print()
