# subscan

A command-line tool for discovering subdomains and checking which TLS versions
their services support.

By default, `subscan` uses passive third-party data sources and does not connect
to the target domain's DNS servers or hosts. The target domain is sent to those
third-party services as part of the queries. Active mode resolves discovered
names and makes TCP connections and TLS handshakes to them. Use active mode only
for domains you are authorized to scan.

## Features

- Collects names from crt.sh, Cert Spotter, AlienVault OTX, and the Internet
  Archive.
- Optionally resolves discovered names and filters names that resolve only
  through wildcard DNS.
- Optionally checks selected TCP ports for support of SSLv3 and TLS 1.0–1.3.
- Prints progress to standard error and reports to standard output.
- Can save results as JSON.

## Requirements

- Python 3.7 or later
- No third-party Python packages; the program uses the standard library.

## Usage

Passive discovery:

```sh
python3 subscan.py example.com
```

Active resolution and TLS checks using the default ports (443 and 8443):

```sh
python3 subscan.py example.com --active
```

Choose ports, timeout, and concurrency, and save the results:

```sh
python3 subscan.py example.com --active --ports 443,8443 --timeout 5 --threads 20 --json results.json
```

Show all options:

```sh
python3 subscan.py --help
```

The JSON output includes the target domain, whether active mode was used,
discovered names and their sources, resolved addresses, wildcard DNS addresses,
and TLS results.

## Data sources

The program queries these public services:

- [crt.sh](https://crt.sh/)
- [Cert Spotter](https://sslmate.com/certspotter/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [Internet Archive](https://web.archive.org/)

Availability, rate limits, and returned data depend on those services.

## Authorization

Passive mode queries third-party services with the domain you provide. Active
mode additionally sends DNS queries and makes TCP/TLS connections to discovered
hosts and the target domain for wildcard-DNS checks. Only run active scans
against systems you own or are explicitly authorized to test.

## License

This project is distributed under the MIT License. See [LICENSE](./LICENSE).
