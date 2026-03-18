import argparse
import json
import sys
from pathlib import Path

from crecon.utils.output import (
    banner, phase, info, success, warn, error, port_line, summary
)
from crecon.core import scanner, recon, enumerator, orchestrator


def handle_callback(event):
    if not isinstance(event, dict):
        return

    if "phase" in event:
        print(f"\n  {phase(event['phase'])}  {event['msg']}")
        return

    if "warning" in event:
        warn(event["warning"])
        return

    # dir scan hit
    if "code" in event and "url" in event:
        code  = event["code"]
        color = "\033[32m" if code == 200 else "\033[33m"
        reset = "\033[0m"
        redir = f"  → {event['redirect']}" if event.get("redirect") else ""
        print(f"    {color}[{code}]{reset}  {event['url']}{redir}")
        return

    # recon page
    if "emails" in event:
        emails = event.get("emails", [])
        tech   = event.get("tech", [])
        if emails:
            for e in emails:
                success(f"email  {e}")
        if tech:
            info(f"tech   {', '.join(tech)}")
        return

    # ssh hit
    if "username" in event:
        success(f"SSH valid  {event['username']}:{event['password']}")
        return


def cmd_scan(args):
    ip = scanner.resolve(args.target)
    if not ip:
        error(f"Cannot resolve {args.target}")
        sys.exit(1)

    info(f"Target  {args.target}  ({ip})")
    info(f"Ports   {args.start}–{args.end}")
    print()

    ports   = list(range(args.start, args.end + 1))
    results = []

    def on_result(r):
        results.append(r)
        if r["state"] == "open":
            port_line(r["port"], r["service"], version=r.get("banner", ""))

    scanner.scan(ip, ports, threads=args.threads,
                 timeout=args.timeout, grab=args.banners, callback=on_result)

    open_ports = [r for r in results if r["state"] == "open"]
    print(f"\n  {len(open_ports)} open port(s) found.\n")

    if args.output:
        Path(args.output).write_text(
            json.dumps(open_ports, indent=2), encoding="utf-8"
        )
        info(f"Saved to {args.output}")


def cmd_recon(args):
    info(f"Target  {args.url}")
    info(f"Pages   up to {args.depth}")
    print()

    results = recon.crawl(
        args.url,
        max_pages = args.depth,
        delay     = 0.5,
        callback  = handle_callback,
    )

    if args.output:
        recon.save_csv(results, args.output)
        info(f"CSV saved to {args.output}")


def cmd_enum(args):
    if args.mode == "dirs":
        info(f"Dir scan  {args.url}")
        print()
        enumerator.dir_scan(
            args.url,
            args.wordlist,
            threads  = args.threads,
            callback = handle_callback,
        )

    elif args.mode == "subs":
        info(f"Subdomain scan  {args.domain}")
        print()
        ns = [s.strip() for s in args.resolvers.split(",") if s.strip()] \
             if args.resolvers else None
        results = enumerator.subdomain_scan(
            args.domain,
            args.wordlist,
            threads     = args.threads,
            nameservers = ns,
            callback    = handle_callback,
        )
        print(f"\n  {len(results)} subdomain(s) found.\n")


def cmd_auto(args):
    info(f"Auto recon  {args.target}")
    info(f"Ports       {args.ports}")
    if args.wordlist:
        info(f"Wordlist    {args.wordlist}")
    print()

    report = orchestrator.run(
        target   = args.target,
        ports    = args.ports,
        wordlist = args.wordlist,
        no_ssh   = args.no_ssh,
        dry_run  = args.dry_run,
        callback = handle_callback,
    )

    summary(report)

    if args.output:
        safe = json.dumps(report, indent=2, default=lambda o: list(o)
                          if isinstance(o, set) else str(o))
        Path(args.output).write_text(safe, encoding="utf-8")
        info(f"Report saved to {args.output}")


def main():
    banner()

    parser = argparse.ArgumentParser(
        prog="crecon",
        description="Automated recon toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────────
    sp = sub.add_parser("scan", help="TCP port scanner")
    sp.add_argument("target")
    sp.add_argument("--start",   type=int,   default=1)
    sp.add_argument("--end",     type=int,   default=1000)
    sp.add_argument("--threads", type=int,   default=100)
    sp.add_argument("--timeout", type=float, default=1.0)
    sp.add_argument("--banners", action="store_true")
    sp.add_argument("--output",  default="")

    # ── recon ─────────────────────────────────────────────────────────────────
    rp = sub.add_parser("recon", help="Web crawler + contact extractor")
    rp.add_argument("--url",    required=True)
    rp.add_argument("--depth",  type=int, default=20)
    rp.add_argument("--output", default="recon.csv")

    # ── enum ──────────────────────────────────────────────────────────────────
    ep = sub.add_parser("enum", help="Directory and subdomain brute-force")
    ep_sub = ep.add_subparsers(dest="mode", required=True)

    dp = ep_sub.add_parser("dirs", help="Directory brute-force")
    dp.add_argument("--url",      required=True)
    dp.add_argument("--wordlist", required=True)
    dp.add_argument("--threads",  type=int, default=15)

    sp2 = ep_sub.add_parser("subs", help="Subdomain enumeration")
    sp2.add_argument("--domain",    required=True)
    sp2.add_argument("--wordlist",  required=True)
    sp2.add_argument("--threads",   type=int, default=20)
    sp2.add_argument("--resolvers", default="")

    # ── auto ──────────────────────────────────────────────────────────────────
    ap = sub.add_parser("auto", help="Full auto recon (chains all tools)")
    ap.add_argument("target")
    ap.add_argument("--ports",    default="1-1024")
    ap.add_argument("--wordlist", default=None)
    ap.add_argument("--no-ssh",   action="store_true")
    ap.add_argument("--dry-run",  action="store_true")
    ap.add_argument("--output",   default="report.json")

    args = parser.parse_args()

    dispatch = {
        "scan":  cmd_scan,
        "recon": cmd_recon,
        "enum":  cmd_enum,
        "auto":  cmd_auto,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()