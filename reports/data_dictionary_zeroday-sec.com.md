# Data Dictionary - Security Scan Results
## Domain: zeroday-sec.com
## Generated: 2025-07-24 08:19:58

---

## Overview
This data dictionary describes the structure and content of the security scan results for **zeroday-sec.com**. The data is organized into five main categories based on the type of information and source tools.

## Data Categories

### Network & DNS Info
**Description**: Network infrastructure and DNS-related information  
**Primary Sources**: nmap, dnsenum, dnsdumpster

| Field Path | Description | Source Tool |
|------------|-------------|-------------|
| `nmap.ip` | IP address or port (string) | nmap |
| `nmap.ports.portid` | IP address or port (string) | nmap |
| `nmap.ports.protocol` | Text value (string) | nmap |
| `nmap.ports.state` | Text value (string) | nmap |
| `nmap.ports.service` | Text value (string) | nmap |
| `dnsdumpster.mx.ips.asn` | IP address or port (string) | dnsdumpster |
| `dnsdumpster.mx.ips.asn_name` | Text value (string) | dnsdumpster |
| `dnsdumpster.mx.ips.asn_range` | Text value (string) | dnsdumpster |
| `dnsdumpster.mx.ips.country` | Text value (string) | dnsdumpster |
| `dnsdumpster.mx.ips.country_code` | Text value (string) | dnsdumpster |
| `dnsdumpster.mx.ips.ip` | IP address or port (string) | dnsdumpster |
| `dnsdumpster.mx.ips.ptr` | Text value (string) | dnsdumpster |
| `dnsdumpster.ns.ips.asn` | IP address or port (string) | dnsdumpster |
| `dnsdumpster.ns.ips.asn_name` | Text value (string) | dnsdumpster |
| `dnsdumpster.ns.ips.asn_range` | Text value (string) | dnsdumpster |
| `dnsdumpster.ns.ips.country` | Text value (string) | dnsdumpster |
| `dnsdumpster.ns.ips.country_code` | Text value (string) | dnsdumpster |
| `dnsdumpster.ns.ips.ip` | IP address or port (string) | dnsdumpster |
| `dnsdumpster.ns.ips.ptr` | Text value (string) | dnsdumpster |
| `dnsdumpster.total_a_recs` | Numeric value (integer) | dnsdumpster |

### Subdomains & Hosts
**Description**: Discovered subdomains and host information  
**Primary Sources**: sublist3r, theharvester, dnsdumpster

| Field Path | Description | Source Tool |
|------------|-------------|-------------|
| `dnsdumpster.a.host` | Text value (string) | dnsdumpster |
| `dnsdumpster.a.ips.asn` | IP address or port (string) | dnsdumpster |
| `dnsdumpster.a.ips.asn_name` | Text value (string) | dnsdumpster |
| `dnsdumpster.a.ips.asn_range` | Text value (string) | dnsdumpster |
| `dnsdumpster.a.ips.country` | Text value (string) | dnsdumpster |
| `dnsdumpster.a.ips.country_code` | Text value (string) | dnsdumpster |
| `dnsdumpster.a.ips.ip` | IP address or port (string) | dnsdumpster |
| `dnsdumpster.a.ips.ptr` | Text value (string) | dnsdumpster |
| `dnsdumpster.cname` | Empty list (array) | dnsdumpster |
| `dnsdumpster.mx.host` | Text value (string) | dnsdumpster |
| `dnsdumpster.ns.host` | Text value (string) | dnsdumpster |

### Emails
**Description**: Email addresses discovered during reconnaissance  
**Primary Sources**: theharvester

| Field Path | Description | Source Tool |
|------------|-------------|-------------|
| `theharvester.emails` | Empty list (array) | theharvester |

### Web Technologies
**Description**: Web technologies and frameworks detected  
**Primary Sources**: whatweb

| Field Path | Description | Source Tool |
|------------|-------------|-------------|
| `whatweb.url` | URL (string) | whatweb |
| `whatweb.status` | Text value (string) | whatweb |
| `whatweb.Email` | Email address (string) | whatweb |
| `whatweb.HTML5` | Boolean flag (boolean) | whatweb |
| `whatweb.HTTPServer` | Text value (string) | whatweb |
| `whatweb.IP` | IP address or port (string) | whatweb |
| `whatweb.LiteSpeed` | Boolean flag (boolean) | whatweb |
| `whatweb.Strict-Transport-Security` | Text value (string) | whatweb |
| `whatweb.Title` | Text value (string) | whatweb |
| `whatweb.UncommonHeaders` | Text value (string) | whatweb |
| `whatweb.X-Frame-Options` | Text value (string) | whatweb |
| `whatweb.X-XSS-Protection` | Text value (string) | whatweb |

### HTTP Headers
**Description**: HTTP response headers and security information  
**Primary Sources**: httpx

| Field Path | Description | Source Tool |
|------------|-------------|-------------|
| `httpx` | Email address (string) | httpx |

---

## Complete Data Structure

The following shows the complete structure of the aggregated results:

```json
{
  "nmap": [
    {
      "ip": "103.191.76.181",
      "ports": [
        {
          "portid": "21",
          "protocol": "tcp",
          "state": "open",
          "service": "ftp"
        },
        {
          "portid": "53",
          "protocol": "tcp",
          "state": "open",
          "service": "domain"
        },
        {
          "portid": "80",
          "protocol": "tcp",
          "state": "open",
          "service": "http"
        },
        {
          "portid": "110",
          "protocol": "tcp",
          "state": "open",
          "service": "pop3"
        },
        {
          "portid": "143",
          "protocol": "tcp",
          "state": "open",
          "service": "imap"
        },
        {
          "portid": "443",
          "protocol": "tcp",
          "state": "open",
          "service": "https"
        },
        {
          "portid": "465",
          "protocol": "tcp",
          "state": "open",
          "service": "smtp"
        },
        {
          "portid": "587",
          "protocol": "tcp",
          "state": "open",
          "service": "smtp"
        },
        {
          "portid": "993",
          "protocol": "tcp",
          "state": "open",
          "service": "imaps"
        },
        {
          "portid": "995",
          "protocol": "tcp",
          "state": "open",
          "service": "pop3s"
        }
      ]
    }
  ],
  "whatweb": {
    "url": "https://zeroday-sec.com/",
    "status": "200 OK",
    "Email": "team@zeroday-sec.com",
    "...": "additional fields"
  },
  "dnsenum": [
    "103.191.76.181",
    "103.191.76.181",
    "103.191.76.181"
  ],
  "theharvester": {
    "emails": [],
    "hosts": [
      "certs.zeroday-sec.com"
    ],
    "ips": [
      "103.191.76.131",
      "110.4.45.109"
    ]
  },
  "httpx": "HTTP/1.1 200 OK\nConnection: Keep-Alive\nKeep-Alive: timeout=5, max=100\ncontent-type: text/html\nlast-modified: Wed, 19 Feb 2025 14:31:55 GMT\naccept-ranges: bytes\ncontent-encoding: br\nvary: Accept-Encoding\ncontent-length: 350\ndate: Thu, 24 Jul 2025 07:20:54 GMT\nserver: LiteSpeed\nx-content-type-options: nosniff\nx-frame-options: SAMEORIGIN\nx-xss-protection: 1;  mode=block\nx-download-options: noopen\nx-permitted-cross-domain-policies: master-only\nx-dns-prefetch-control: on\nreferrer-policy: no-referrer-when-downgrade\nstrict-transport-security: max-age=31536000\ncontent-security-policy: block-all-mixed-content\nalt-svc: h3=\":443\"; ma=2592000, h3-29=\":443\"; ma=2592000, h3-Q050=\":443\"; ma=2592000, h3-Q046=\":443\"; ma=2592000, h3-Q043=\":443\"; ma=2592000, quic=\":443\"; ma=2592000; v=\"43,46\"\n\n<!doctype html>\n<title>Site Maintenance</title>\n<style>\n  body { text-align: center; padding: 150px; }\n  h1 { font-size: 50px; }\n  body { font: 20px Helvetica, sans-serif; color: #333; }\n  article { display: block; text-align: left; width: 650px; margin: 0 auto; }\n  a { color: #dc8100; text-decoration: none; }\n  a:hover { color: #333; text-decoration: none; }\n</style>\n\n<article>\n    <h1>We&rsquo;ll be back soon!</h1>\n    <div>\n        <p>Sorry for the inconvenience but we&rsquo;re performing some maintenance at the moment. If you need to you can always <a href=\"mailto:team@zeroday-sec.com\">contact \nus</a>, otherwise we&rsquo;ll be back online shortly!</p>\n        <p>&mdash; 0day Team</p>\n    </div>\n</article>\n",
  "sublist3r": [
    "www.zeroday-sec.com",
    "academy.zeroday-sec.com",
    "certs.zeroday-sec.com"
  ],
  "dnsdumpster": {
    "a": [
      {
        "host": "certs.zeroday-sec.com",
        "ips": [
          {
            "asn": "136727",
            "asn_name": "JTS-AS-AP Jimat Technology Solution, MY",
            "asn_range": "103.191.76.0/24",
            "country": "Malaysia",
            "country_code": "MY",
            "ip": "103.191.76.181",
            "ptr": ""
          }
        ]
      },
      {
        "host": "www.certs.zeroday-sec.com",
        "ips": [
          {
            "asn": "136727",
            "asn_name": "JTS-AS-AP Jimat Technology Solution, MY",
            "asn_range": "103.191.76.0/24",
            "country": "Malaysia",
            "country_code": "MY",
            "ip": "103.191.76.181",
            "ptr": ""
          }
        ]
      },
      {
        "host": "webmail.zeroday-sec.com",
        "ips": [
          {
            "asn": "136727",
            "asn_name": "JTS-AS-AP Jimat Technology Solution, MY",
            "asn_range": "103.191.76.0/24",
            "country": "Malaysia",
            "country_code": "MY",
            "ip": "103.191.76.181",
            "ptr": ""
          }
        ]
      }
    ],
    "cname": [],
    "mx": [
      {
        "host": "0 zeroday-sec.com",
        "ips": [
          {
            "asn": "136727",
            "asn_name": "JTS-AS-AP Jimat Technology Solution, MY",
            "asn_range": "103.191.76.0/24",
            "country": "Malaysia",
            "country_code": "MY",
            "ip": "103.191.76.181",
            "ptr": ""
          }
        ]
      }
    ],
    "...": "additional fields"
  }
}
```

---

## Tool Sources

### Network & DNS Scanning Tools
- **nmap**: Network port scanner and service detection
- **dnsenum**: DNS enumeration and zone transfer attempts  
- **dnsdumpster**: DNS reconnaissance and subdomain discovery

### Subdomain & Host Discovery Tools
- **sublist3r**: Subdomain enumeration using OSINT
- **theharvester**: Email, subdomain and host OSINT gathering
- **dnsdumpster**: DNS record analysis for subdomains

### Email Discovery Tools
- **theharvester**: Email address harvesting from public sources

### Web Technology Detection Tools
- **whatweb**: Web application technology fingerprinting

### HTTP Analysis Tools
- **httpx**: HTTP header analysis and security assessment

---

## Data Quality Notes

- **Total data sources processed**: 7
- **Available data sources**: nmap, whatweb, dnsenum, theharvester, httpx, sublist3r, dnsdumpster

---

## Usage Notes

1. **Empty Arrays**: Empty arrays (`[]`) indicate the tool ran but found no results
2. **Missing Keys**: Missing tool sections indicate the tool failed to run or produce output
3. **Nested Data**: Some tools produce nested data structures - refer to field paths for navigation
4. **Data Types**: All data is JSON-serializable (strings, numbers, booleans, arrays, objects)

---

*This data dictionary was automatically generated based on the actual scan results for zeroday-sec.com.*
