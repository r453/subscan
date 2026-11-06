#!/usr/bin/env python3
"""
subscan.py - subdomain discovery and TLS version analysis.

Usage:
    python3 subscan.py domain.com                    # passive by default
    python3 subscan.py domain.com --active           # + resolution, port check, TLS
    python3 subscan.py domain.com --active --ports 443,8443 --json results.json

Dependencies: Python standard library only.

Modes:
  (default)  Passive: queries only third-party data sources
             (CT logs, etc.). Does NOT contact the target domain's DNS
             servers or hosts.
  --active   Active: resolves hosts and makes TCP connections and TLS handshakes
             to targets. Use only for domains you are authorized to scan.

During execution, a spinner on stderr shows the current phase, progress, and
elapsed time. Output is written to stdout, so it can be redirected to a file.
"""

import argparse
import json
import random
import re
import shutil
import socket
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

# Testing old TLS versions is intentional; suppress deprecation warnings.
warnings.filterwarnings("ignore", message=r"ssl\.TLSVersion\..* is deprecated",
                        category=DeprecationWarning)

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
USER_AGENT = "subscan/0.1 (+passive subdomain enumeration)"

# TLS versions to test (oldest to newest)
TLS_VERSIONS = [
    ("SSLv3", ssl.TLSVersion.SSLv3),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


class Status:
    """Live indicator: spinner, phase, and elapsed time on stderr.

    In a non-interactive environment (stderr redirected to a file), the spinner
    is not drawn; phases are printed as regular lines instead.
    """
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self):
        self.msg = ""
        self.t0 = time.time()
        self.tty = sys.stderr.isatty()
        self.lock = threading.Lock()
        self.stop_ev = threading.Event()
        self.thread = None
        self.drawn = 0

    def _clear(self):  # Call while holding the lock.
        if self.tty and self.drawn:
            sys.stderr.write("\r" + " " * self.drawn + "\r")
            sys.stderr.flush()
            self.drawn = 0

    def _draw(self, frame):  # Call while holding the lock.
        elapsed = int(time.time() - self.t0)
        line = f"{frame} {self.msg} [{elapsed // 60:02d}:{elapsed % 60:02d}]"
        line = line[: shutil.get_terminal_size((80, 20)).columns - 1]
        sys.stderr.write("\r" + line.ljust(self.drawn))
        sys.stderr.flush()
        self.drawn = len(line)

    def _run(self):
        i = 0
        while not self.stop_ev.wait(0.1):
            with self.lock:
                self._draw(self.FRAMES[i % len(self.FRAMES)])
            i += 1

    def start(self, msg="Starting"):
        self.msg = msg
        self.t0 = time.time()
        if self.tty:
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()

    def set(self, msg, announce=True):
        """Set the status message. announce=False updates only the spinner."""
        with self.lock:
            self.msg = msg
            if announce and not self.tty:
                print(f"[*] {msg}", file=sys.stderr, flush=True)

    def log(self, msg):
        """Print a line without interfering with the spinner."""
        with self.lock:
            self._clear()
            print(msg, file=sys.stderr, flush=True)

    def stop(self):
        self.stop_ev.set()
        if self.thread:
            self.thread.join()
        with self.lock:
            self._clear()


STATUS = Status()


def log(msg):
    STATUS.log(msg)


# --------------------------------------------------------------------------
# 1. DISCOVERY (passive sources)
# --------------------------------------------------------------------------

def http_get_json(url, timeout=30, retries=4):
    """GET and parse JSON. Retry transient errors with exponential backoff."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(retries):
        last = attempt == retries - 1
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or last:
                raise
            reason = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if last:
                raise
            reason = str(e)
        wait = 2 ** (attempt + 1)  # 2, 4, 8 seconds
        log(f"    retry {attempt + 1}/{retries - 1} ({reason}); waiting {wait}s")
        time.sleep(wait)


def normalize(names, domain):
    """Normalize names: lowercase, remove wildcards, keep only domain subdomains."""
    out = set()
    for n in names:
        n = n.strip().lower().lstrip("*.").rstrip(".")
        if n == domain or n.endswith("." + domain):
            if re.fullmatch(r"[a-z0-9._-]+", n):
                out.add(n)
    return out


def source_crtsh(domain):
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + domain) + "&output=json"
    data = http_get_json(url, timeout=60)
    names = []
    for row in data:
        names.extend(row.get("name_value", "").splitlines())
    return normalize(names, domain)


def source_certspotter(domain):
    url = ("https://api.certspotter.com/v1/issuances?domain="
           + urllib.parse.quote(domain)
           + "&include_subdomains=true&expand=dns_names")
    data = http_get_json(url)
    names = []
    for row in data:
        names.extend(row.get("dns_names", []))
    return normalize(names, domain)


def source_otx(domain):
    """AlienVault OTX passive DNS (no API key required)."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    data = http_get_json(url)
    return normalize([row.get("hostname", "") for row in data.get("passive_dns", [])], domain)


def source_wayback(domain):
    """Hostnames extracted from URLs archived by the Internet Archive."""
    url = ("https://web.archive.org/cdx/search/cdx?url=*." + urllib.parse.quote(domain)
           + "&output=json&fl=original&collapse=urlkey&limit=50000")
    rows = http_get_json(url, timeout=90)[1:]  # [1:] skips the header row
    hosts = [urllib.parse.urlparse(r[0]).hostname or "" for r in rows]
    return normalize(hosts, domain)


# Add new sources here: name -> function(domain) -> set[str]
SOURCES = {
    "crt.sh": source_crtsh,
    "certspotter": source_certspotter,
    "otx": source_otx,
    "wayback": source_wayback,
}


def discover(domain):
    """Return all names and a mapping of each name to its sources."""
    found = {}
    total = len(SOURCES)
    for i, (name, fn) in enumerate(SOURCES.items(), 1):
        STATUS.set(f"Fetching from {name} ({i}/{total})")
        try:
            names = fn(domain)
            log(f"[+] {name}: {len(names)} names")
        except Exception as e:  # A failure in one source must not abort the entire run.
            log(f"[!] {name} failed: {type(e).__name__}: {e}")
            continue
        for n in names:
            found.setdefault(n, []).append(name)
    return found


# --------------------------------------------------------------------------
# 2. RESOLUTION + wildcard filtering (active)
# --------------------------------------------------------------------------

def resolve(host):
    """Return a set of IP addresses (A + AAAA), or an empty set if unresolved."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return {i[4][0] for i in infos}
    except socket.gaierror:
        return set()


def wildcard_ips(domain, tries=2):
    """Resolve random names; if they return records, the domain has wildcard DNS."""
    ips = set()
    for _ in range(tries):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        ips |= resolve(f"{label}.{domain}")
    return ips


def resolve_all(names, domain, threads):
    STATUS.set("Checking wildcard DNS")
    wc = wildcard_ips(domain)
    if wc:
        log(f"[!] Wildcard DNS detected ({', '.join(sorted(wc))}); "
            "names resolving only via the wildcard will be filtered out")
    resolved = {}
    total = len(names)
    STATUS.set(f"Resolving {total} names")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(resolve, n): n for n in names}
        for done, f in enumerate(as_completed(futs), 1):
            STATUS.set(f"Resolving names {done}/{total}", announce=False)
            n, ips = futs[f], f.result()
            if not ips:
                continue
            if wc and ips <= wc:
                continue  # Matches only the wildcard; likely not a real record.
            resolved[n] = sorted(ips)
    return resolved, sorted(wc)


# --------------------------------------------------------------------------
# 3. PROBE (TCP) and 4. TLS analysis (active)
# --------------------------------------------------------------------------

def tcp_open(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def try_tls(host, port, version, timeout):
    """
    Attempt a handshake while forcing a single TLS version.
    Return: 'yes' | 'no' | 'n/a' (the local OpenSSL does not support the version).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError):
        return "n/a"
    if version < ssl.TLSVersion.TLSv1_2:
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            return "n/a"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # server_hostname enables SNI, which is important for shared IPs.
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return "yes" if tls.version() else "no"
    except ssl.SSLError:
        return "no"   # Note: this may also mean the local OpenSSL does not support the version.
    except OSError:
        return "no"


def analyze_host(host, ports, timeout):
    result = {"host": host, "ports": {}}
    for port in ports:
        if not tcp_open(host, port, timeout):
            continue
        versions = {name: try_tls(host, port, v, timeout) for name, v in TLS_VERSIONS}
        # If all results are 'no', the port probably does not speak TLS (e.g. HTTP/STARTTLS).
        result["ports"][port] = versions
    return result


def analyze_all(hosts, ports, timeout, threads):
    out = []
    total = len(hosts)
    STATUS.set(f"Testing TLS versions ({total} hosts)")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(analyze_host, h, ports, timeout) for h in hosts]
        for done, f in enumerate(as_completed(futs), 1):
            STATUS.set(f"TLS test complete for {done}/{total} hosts", announce=False)
            out.append(f.result())
    return sorted(out, key=lambda r: r["host"])


# --------------------------------------------------------------------------
# 5. REPORT
# --------------------------------------------------------------------------

def print_section(title):
    print(f"\n=== {title} ===")


def print_report(domain, found, resolved, wildcard, tls, passive):
    print_section(f"Discovered subdomains ({len(found)})")
    for n in sorted(found):
        print(f"{n:50} [{', '.join(found[n])}]")

    if passive:
        return

    print_section(f"Active (resolvable) subdomains ({len(resolved)})")
    for n in sorted(resolved):
        print(f"{n:50} {', '.join(resolved[n])}")

    tls_hosts = [r for r in tls if r["ports"]]
    print_section(f"TLS versions ({len(tls_hosts)} hosts with an open port)")
    header = "".join(f"{name:9}" for name, _ in TLS_VERSIONS)
    print(f"{'host:port':55}{header}")
    sym = {"yes": "YES", "no": "-", "n/a": "?"}
    for r in tls_hosts:
        for port, versions in sorted(r["ports"].items()):
            cols = "".join(f"{sym[versions[name]]:9}" for name, _ in TLS_VERSIONS)
            print(f"{r['host'] + ':' + str(port):55}{cols}")
    print("\n'?' = the local OpenSSL does not support the version; '-' = unsupported "
          "(or the port does not speak TLS).")


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Subdomain discovery and TLS versions.")
    p.add_argument("domain", help="target domain, e.g. domain.com")
    p.add_argument("--active", action="store_true",
                   help="active scan: resolution, port check, and TLS versions "
                        "(default: passive sources only; no connections to the target)")
    p.add_argument("--ports", default="443,8443",
                   help="comma-separated TLS ports (default: 443,8443)")
    p.add_argument("--timeout", type=float, default=5.0, help="timeout in seconds")
    p.add_argument("--threads", type=int, default=20, help="number of concurrent threads")
    p.add_argument("--json", metavar="FILE", help="save results to a JSON file")
    return p.parse_args()


def main():
    args = parse_args()
    domain = args.domain.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        sys.exit(f"Invalid domain: {domain}")
    try:
        ports = [int(x) for x in args.ports.split(",") if x.strip()]
    except ValueError:
        sys.exit("Invalid --ports value")

    if args.active:
        log("[!] Active mode: connections will be made to targets. "
            "Use only if you are authorized to scan them.")
    else:
        log("[*] Passive mode (default): no connections will be made to the target.")

    found, resolved, wildcard, tls = {}, {}, [], []
    STATUS.start("Starting")
    try:
        # 1. Discovery
        found = discover(domain)
        if args.active:
            # 2. Resolve
            resolved, wildcard = resolve_all(list(found), domain, args.threads)
            # 3 + 4. Probe + TLS
            tls = analyze_all(sorted(resolved), ports, args.timeout, args.threads)
    finally:
        STATUS.stop()

    # 5. Report
    print_report(domain, found, resolved, wildcard, tls, passive=not args.active)
    if not args.active:
        log("\n[*] To perform resolution, port checks, and TLS version tests, rerun with --active.")

    # Tip: inspect an individual subdomain's TLS details with nmap (using a real result as an example).
    example_host, example_port = domain, 443
    for r in tls:
        if r["ports"]:
            example_host, example_port = r["host"], sorted(r["ports"])[0]
            break
    else:
        if resolved:
            example_host = sorted(resolved)[0]
        elif found:
            example_host = sorted(found)[0]
    log("\n[*] Tip: inspect subdomain-specific TLS details (supported versions and ciphers) "
        "in more detail from the command line, for example:\n"
        f"      nmap -p {example_port} --script ssl-enum-ciphers {example_host}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({
                "domain": domain,
                "active": args.active,
                "discovered": found,
                "resolved": resolved,
                "wildcard_ips": wildcard,
                "tls": tls,
            }, f, indent=2, ensure_ascii=False)
        log(f"[+] JSON saved: {args.json}")


if __name__ == "__main__":
    main()
