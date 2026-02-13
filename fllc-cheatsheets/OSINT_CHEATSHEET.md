# OSINT Cheatsheet

> Open-Source Intelligence techniques for security professionals.
> FLLC 2026 — FU PERSON

---

## Search Engine Dorking

### Google Dorks
```
site:target.com                    # All indexed pages
site:target.com filetype:pdf       # PDFs only
site:target.com inurl:admin        # Admin pages
site:target.com intitle:"index of" # Directory listings
site:target.com ext:sql            # SQL files
"target.com" password              # Exposed credentials
"target.com" inurl:api             # API endpoints
intext:"@target.com" filetype:xlsx # Email lists in spreadsheets
```

### Shodan Dorks
```
hostname:target.com                # All assets
org:"Target Corp"                  # By organization
ssl.cert.subject.CN:target.com     # SSL certificates
http.title:"Dashboard"             # Web dashboards
port:3389 country:US               # RDP servers
"default password" port:80         # Default creds
product:"Apache" version:"2.4.49"  # Specific CVE targets
```

---

## Tools

| Tool | Purpose |
|------|---------|
| **theHarvester** | Email, subdomain, IP enumeration |
| **Maltego** | Visual link analysis |
| **Recon-ng** | Reconnaissance framework |
| **SpiderFoot** | Automated OSINT |
| **Sherlock** | Username search across 300+ sites |
| **GHunt** | Google account investigation |
| **Holehe** | Email to account registration checker |
| **Maigret** | Username across 2500+ sites |
| **ExifTool** | Image metadata extraction |
| **Metagoofil** | Document metadata harvester |

---

## Domain Recon

```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt
amass enum -d target.com
assetfinder target.com

# DNS records
dig target.com ANY
dig target.com MX
dig target.com TXT
host -t ns target.com

# Zone transfer attempt
dig axfr target.com @ns1.target.com

# Certificate transparency
curl "https://crt.sh/?q=%25.target.com&output=json" | jq '.[].name_value'

# Wayback Machine
waybackurls target.com | sort -u
```

---

## People Search

| Resource | Data Type |
|----------|-----------|
| LinkedIn | Professional info, connections |
| WhitePages | Phone, address |
| Pipl | Cross-platform aggregation |
| ThatsThem | Phone, email, address |
| PublicRecords | Court records, property |
| Social Searcher | Social media posts |
| Namechk | Username availability |
| Hunter.io | Email finder by domain |

---

## Image OSINT

```bash
# Reverse image search
# Google Images, TinEye, Yandex, Bing Visual

# Extract EXIF data
exiftool image.jpg

# Key EXIF fields
# GPS coordinates
# Camera model
# Timestamp
# Software used
```

---

## Social Media OSINT

| Platform | Technique |
|----------|-----------|
| Twitter/X | Advanced search: `from:user since:2025-01-01` |
| Instagram | Web viewer, story archives, tagged locations |
| Facebook | Graph search, public posts, group memberships |
| LinkedIn | Company employees, job history, connections |
| Reddit | User history: `reddit.com/user/USERNAME` |
| GitHub | Commit emails, repo history, gist secrets |

---

## Email Investigation

```bash
# Email header analysis
# Check Received: headers for originating IP
# Verify SPF, DKIM, DMARC alignment

# Hunter.io — find emails by domain
curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY"

# Have I Been Pwned
curl "https://haveibeenpwned.com/api/v3/breachedaccount/email@target.com"
```

---

**FLLC 2026** — FU PERSON by PERSON FU
