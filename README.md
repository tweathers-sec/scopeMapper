# ScopeMapper

ScopeMapper is a Go-based utility for penetration testers to correlate in-scope IP addresses with subdomains/vhosts. It efficiently maps potential targets within defined network boundaries, supporting multiple output formats.

## Features

- Correlate in-scope IPs with subdomains/vhosts
- Support for IP ranges (CIDR notation)
- Multiple output formats (txt, json, xml, csv)
- Easy-to-use command-line interface

## Build Instructions

1. Ensure you have Go installed (version 1.13+)
2. Clone the repository:

```
git clone https://github.com/tweathers-sec/scopeMapper.git
```

3. Navigate to the project directory:

```
cd scopemapper
```

4. Build the binary:

```
go mod init scopemapper
go mod tidy
go build -o scopemapper
```

## Usage

### Basic Usage

```
./scopemapper -ips in_scope_ips.txt -domains potential_domains.txt -output results.json -format json
```

### Create In-Scope Subdomains List

```
./scopemapper -portscan -input results.json -output inscope_subdomains.txt
```

### Flags

- `-ips`: File containing in-scope IP addresses/CIDRs
- `-domains`: File containing potential in-scope vhosts/subdomains
- `-output`: Output file name (optional)
- `-format`: Output format (txt, json, xml, csv) (default: txt)
- `-portscan`: Create an in-scope subdomains txt file from a ScopeMapper output file
- `-input`: Input file for portscan option (required when using -portscan)

## Example

1. Create a file `in_scope_ips.txt` with IP addresses and ranges:

```
192.168.1.1
10.0.0.0/24
```

2. Create a file `potential_domains.txt` with subdomains/vhosts:

```
subdomain1.example.com
subdomain2.example.com
```

3. Run ScopeMapper:

```
./scopemapper -ips in_scope_ips.txt -domains potential_domains.txt -output results.json -format json
```

4. Check the results in `results.json`

5. Create an in-scope subdomains list from the results:

```
./scopemapper -portscan -input results.json -output inscope_subdomains.txt
```

6. Check the in-scope subdomains in `inscope_subdomains.txt`
