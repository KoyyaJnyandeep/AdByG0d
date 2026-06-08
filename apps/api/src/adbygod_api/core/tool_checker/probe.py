"""Tool availability probe — checks which attack tools are installed."""
from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field


@dataclass
class ToolSpec:
    name: str
    binary: str
    install_cmd: str
    phases: list[int]
    version_flag: str = "--version"


@dataclass
class ToolResult:
    name: str
    binary: str
    available: bool
    version: str | None
    install_cmd: str
    phases: list[int] = field(default_factory=list)


# Phase legend:
#  0 = Recon  1 = Initial Access  2 = Enumeration  3 = PrivEsc
#  4 = Lateral Movement  5 = Persistence  6 = Loot  7 = Evasion

TOOL_CATALOG: list[ToolSpec] = [

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 0 — RECONNAISSANCE
    # ════════════════════════════════════════════════════════════════════════

    # Network discovery
    ToolSpec("arp-scan",     "arp-scan",    "apt install arp-scan",           [0]),
    ToolSpec("dig",          "dig",         "apt install dnsutils",           [0]),
    ToolSpec("fping",        "fping",       "apt install fping",              [0]),
    ToolSpec("hping3",       "hping3",      "apt install hping3",             [0, 1]),
    ToolSpec("masscan",      "masscan",     "apt install masscan",            [0]),
    ToolSpec("naabu",        "naabu",       "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", [0], "-version"),
    ToolSpec("nbtscan",      "nbtscan",     "apt install nbtscan",            [0], "-V"),
    ToolSpec("netdiscover",  "netdiscover", "apt install netdiscover",        [0]),
    ToolSpec("nmap",         "nmap",        "apt install nmap",               [0, 1, 2]),
    ToolSpec("nslookup",     "nslookup",    "apt install dnsutils",           [0]),
    ToolSpec("p0f",          "p0f",         "apt install p0f",                [0]),
    ToolSpec("tcpdump",      "tcpdump",     "apt install tcpdump",            [0]),
    ToolSpec("tshark",       "tshark",      "apt install tshark",             [0]),
    ToolSpec("whois",        "whois",       "apt install whois",              [0]),
    ToolSpec("wireshark",    "wireshark",   "apt install wireshark",          [0]),

    # DNS / subdomain
    ToolSpec("amass",        "amass",       "go install github.com/owasp-amass/amass/v4/...@master", [0], "-version"),
    ToolSpec("assetfinder",  "assetfinder", "go install github.com/tomnomnom/assetfinder@latest", [0], "-h"),
    ToolSpec("dnsx",         "dnsx",        "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", [0], "-version"),
    ToolSpec("dnsrecon",     "dnsrecon",    "pip3 install dnsrecon",          [0]),
    ToolSpec("dnstwist",     "dnstwist",    "apt install dnstwist",           [0]),
    ToolSpec("fierce",       "fierce",      "pip3 install fierce",            [0], "--help"),
    ToolSpec("subfinder",    "subfinder",   "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", [0], "-version"),

    # Web recon
    ToolSpec("aquatone",     "aquatone",    "go install github.com/michenriksen/aquatone@latest",     [0]),
    ToolSpec("dirb",         "dirb",        "apt install dirb",               [0], "--help"),
    ToolSpec("dirsearch",    "dirsearch",   "pip3 install dirsearch",         [0], "--version"),
    ToolSpec("eyewitness",   "eyewitness",  "apt install eyewitness",         [0], "--help"),
    ToolSpec("feroxbuster",  "feroxbuster", "apt install feroxbuster",        [0]),
    ToolSpec("ffuf",         "ffuf",        "apt install ffuf",               [0], "-V"),
    ToolSpec("gau",          "gau",         "go install github.com/lc/gau/v2/cmd/gau@latest",        [0], "--version"),
    ToolSpec("gobuster",     "gobuster",    "apt install gobuster",           [0], "version"),
    ToolSpec("gospider",     "gospider",    "go install github.com/jaeles-project/gospider@latest",   [0], "version"),
    ToolSpec("hakrawler",    "hakrawler",   "go install github.com/hakluke/hakrawler@latest",         [0], "-h"),
    ToolSpec("httpx",        "httpx",       "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", [0], "-version"),
    ToolSpec("katana",       "katana",      "go install github.com/projectdiscovery/katana/cmd/katana@latest", [0], "-version"),
    ToolSpec("nikto",        "nikto",       "apt install nikto",              [0]),
    ToolSpec("nuclei",       "nuclei",      "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", [0], "-version"),
    ToolSpec("recon-ng",     "recon-ng",    "apt install recon-ng",           [0]),
    ToolSpec("snmpwalk",     "snmpwalk",    "apt install snmp",               [0], "-V"),
    ToolSpec("telnet",       "telnet",      "apt install telnet",             [0]),
    ToolSpec("theHarvester", "theHarvester","pip3 install theHarvester",      [0]),
    ToolSpec("wafw00f",      "wafw00f",     "pip3 install wafw00f",           [0]),
    ToolSpec("whatweb",      "whatweb",     "apt install whatweb",            [0]),
    ToolSpec("wfuzz",        "wfuzz",       "apt install wfuzz",              [0]),
    ToolSpec("wpscan",       "wpscan",      "apt install wpscan",             [0]),

    # Kerberos user enumeration
    ToolSpec("kerbrute",     "kerbrute",    "apt install kerbrute",           [0, 1, 3], "version"),

    # OSINT misc
    ToolSpec("username-anarchy","username-anarchy","gem install username-anarchy",[0, 3], "--help"),

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 1 — INITIAL ACCESS
    # ════════════════════════════════════════════════════════════════════════

    # NTLM relay / capture
    ToolSpec("bettercap",       "bettercap",      "apt install bettercap",                [1]),
    ToolSpec("coercer",         "coercer",         "pip3 install coercer",                 [1]),
    ToolSpec("dfscoerce",       "dfscoerce.py",    "git clone https://github.com/Wh04m1001/DFSCoerce", [1], "--help"),
    ToolSpec("impacket-karmaSMB","impacket-karmaSMB","pip3 install impacket",             [1], "-h"),
    ToolSpec("impacket-ntlmrelayx","impacket-ntlmrelayx","pip3 install impacket",         [1, 4]),
    ToolSpec("impacket-smbserver","impacket-smbserver","pip3 install impacket",           [1, 4], "-h"),
    ToolSpec("krbrelayx",       "krbrelayx",       "pip3 install krbrelayx",               [1, 3], "--help"),
    ToolSpec("mitm6",           "mitm6",           "pip3 install mitm6",                   [1]),
    ToolSpec("petitpotam",      "petitpotam.py",   "git clone https://github.com/topotam/PetitPotam", [1]),
    ToolSpec("responder",       "responder",       "pip3 install responder",               [1, 4]),

    # Brute force / spray
    ToolSpec("crowbar",    "crowbar",    "apt install crowbar",        [1, 3]),
    ToolSpec("hydra",      "hydra",      "apt install hydra",          [1, 3]),
    ToolSpec("medusa",     "medusa",     "apt install medusa",         [1, 3]),
    ToolSpec("o365spray",  "o365spray",  "pip3 install o365spray",     [1], "--version"),
    ToolSpec("patator",    "patator",    "apt install patator",         [1, 3], "--help"),
    ToolSpec("smartbrute", "smartbrute", "pip3 install smartbrute",    [1, 3], "--help"),
    ToolSpec("spray",      "spray",      "go install github.com/Greenwolf/Spray@latest",   [1, 3], "--help"),
    ToolSpec("sprayhound", "sprayhound", "pip3 install sprayhound",    [1, 3], "--help"),

    # Phishing / social eng
    ToolSpec("evilginx3",   "evilginx3",   "go install github.com/kgretzky/evilginx/v3@latest", [1]),
    ToolSpec("gophish",     "gophish",     "apt install gophish",      [1]),
    ToolSpec("ruler",       "ruler",       "go install github.com/sensepost/ruler@latest",       [1, 2], "--version"),
    ToolSpec("setoolkit",   "setoolkit",   "apt install set",          [1]),
    ToolSpec("swaks",       "swaks",       "apt install swaks",        [1]),

    # Exploit
    ToolSpec("msfconsole",   "msfconsole",  "apt install metasploit-framework", [1, 4, 7]),
    ToolSpec("msfvenom",     "msfvenom",    "apt install metasploit-framework", [1, 7]),
    ToolSpec("searchsploit", "searchsploit","apt install exploitdb",             [1]),
    ToolSpec("sqlmap",       "sqlmap",      "apt install sqlmap",               [1]),

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 2 — ENUMERATION
    # ════════════════════════════════════════════════════════════════════════

    # AD / LDAP enumeration
    ToolSpec("adalanche",         "adalanche",        "go install github.com/lkarlslund/Adalanche@latest", [2]),
    ToolSpec("adidnsdump",        "adidnsdump",       "pip3 install adidnsdump",          [2], "--help"),
    ToolSpec("bloodhound-python", "bloodhound-python","pip3 install bloodhound",          [2]),
    ToolSpec("enum4linux-ng",     "enum4linux-ng",    "pip3 install enum4linux-ng",        [2]),
    ToolSpec("finduncommonshares","findUncommonShares","pip3 install finduncommonshares", [2], "--help"),
    ToolSpec("ldapdomaindump",    "ldapdomaindump",   "pip3 install ldapdomaindump",       [2], "--help"),
    ToolSpec("ldapsearch",        "ldapsearch",       "apt install ldap-utils",            [2]),
    ToolSpec("ldeep",             "ldeep",            "pip3 install ldeep",                [2], "--help"),
    ToolSpec("manspider",         "manspider",        "pip3 install manspider",            [2], "--help"),
    ToolSpec("neo4j",             "neo4j",            "apt install neo4j",                 [2]),
    ToolSpec("nxc",               "nxc",              "pip3 install netexec",              [2, 3, 4, 6]),
    ToolSpec("rpcclient",         "rpcclient",        "apt install samba-common-bin",      [2]),
    ToolSpec("rusthound",         "rusthound",        "cargo install rusthound",           [2]),
    ToolSpec("smbclient",         "smbclient",        "apt install smbclient",             [2]),
    ToolSpec("smbmap",            "smbmap",           "pip3 install smbmap",               [2]),
    ToolSpec("windapsearch",      "windapsearch",     "go install github.com/ropnop/windapsearch@latest", [2], "--help"),

    # Impacket enumeration
    ToolSpec("impacket-DumpNTLMInfo",  "impacket-DumpNTLMInfo",   "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-GetADComputers","impacket-GetADComputers",  "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-GetADUsers",    "impacket-GetADUsers",      "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-getArch",       "impacket-getArch",         "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-Get-GPPPassword","impacket-Get-GPPPassword","pip3 install impacket", [2, 3], "-h"),
    ToolSpec("impacket-lookupsid",     "impacket-lookupsid",       "pip3 install impacket", [0, 2]),
    ToolSpec("impacket-machine_role",  "impacket-machine_role",    "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-mqtt_check",    "impacket-mqtt_check",      "pip3 install impacket", [0, 2], "-h"),
    ToolSpec("impacket-mssqlinstance", "impacket-mssqlinstance",   "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-net",           "impacket-net",             "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-netview",       "impacket-netview",         "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-rdp_check",     "impacket-rdp_check",       "pip3 install impacket", [0, 2], "-h"),
    ToolSpec("impacket-rpcmap",        "impacket-rpcmap",          "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-rpcdump",       "impacket-rpcdump",         "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-samrdump",      "impacket-samrdump",        "pip3 install impacket", [2], "-h"),
    ToolSpec("impacket-smbclient",     "impacket-smbclient",       "pip3 install impacket", [2, 4], "-h"),
    ToolSpec("impacket-sniff",         "impacket-sniff",           "pip3 install impacket", [0, 2], "-h"),
    ToolSpec("impacket-sniffer",       "impacket-sniffer",         "pip3 install impacket", [0, 2], "-h"),
    ToolSpec("impacket-wmiquery",      "impacket-wmiquery",        "pip3 install impacket", [2], "-h"),

    # Network state (local)
    ToolSpec("netstat", "netstat", "apt install net-tools",  [2]),
    ToolSpec("ss",      "ss",      "apt install iproute2",   [2]),

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 3 — PRIVILEGE ESCALATION
    # ════════════════════════════════════════════════════════════════════════

    # ADCS / Kerberos attacks
    ToolSpec("bloodyad",             "bloodyAD",                "pip3 install bloodyad",       [3], "--help"),
    ToolSpec("certipy",              "certipy",                 "pip3 install certipy-ad",      [3]),
    ToolSpec("certsync",             "certsync",                "pip3 install certsync",        [3], "--help"),
    ToolSpec("crackmapexec",         "crackmapexec",            "pip3 install crackmapexec",    [2, 3, 4]),
    ToolSpec("linpeas",              "linpeas",                 "apt install peass",            [3]),
    ToolSpec("pspy",                 "pspy",                    "Download: github.com/DominicBreuker/pspy/releases", [3], "--help"),
    ToolSpec("pywhisker",            "pywhisker",               "pip3 install pywhisker",       [3], "--help"),
    ToolSpec("targetedkerberoast",   "targetedkerberoast.py",   "pip3 install targetedkerberoast",[3], "--help"),

    # Impacket PrivEsc
    ToolSpec("impacket-addcomputer",   "impacket-addcomputer",    "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-changepasswd",  "impacket-changepasswd",   "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-dacledit",      "impacket-dacledit",       "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-describeTicket","impacket-describeTicket",  "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-exchanger",     "impacket-exchanger",      "pip3 install impacket", [1, 3], "-h"),
    ToolSpec("impacket-findDelegation","impacket-findDelegation",  "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-GetLAPSPassword","impacket-GetLAPSPassword","pip3 install impacket", [3, 6], "-h"),
    ToolSpec("impacket-GetNPUsers",    "impacket-GetNPUsers",     "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-getPac",        "impacket-getPac",         "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-getST",         "impacket-getST",          "pip3 install impacket", [3]),
    ToolSpec("impacket-getTGT",        "impacket-getTGT",         "pip3 install impacket", [3]),
    ToolSpec("impacket-GetUserSPNs",   "impacket-GetUserSPNs",    "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-goldenPac",     "impacket-goldenPac",      "pip3 install impacket", [3]),
    ToolSpec("impacket-keylistattack", "impacket-keylistattack",  "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-owneredit",     "impacket-owneredit",      "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-raiseChild",    "impacket-raiseChild",     "pip3 install impacket", [3]),
    ToolSpec("impacket-rbcd",          "impacket-rbcd",           "pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-secretsdump",   "impacket-secretsdump",    "pip3 install impacket", [3, 6]),
    ToolSpec("impacket-ticketConverter","impacket-ticketConverter","pip3 install impacket", [3], "-h"),
    ToolSpec("impacket-ticketer",      "impacket-ticketer",       "pip3 install impacket", [3], "-h"),

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 4 — LATERAL MOVEMENT
    # ════════════════════════════════════════════════════════════════════════

    # Tunneling
    ToolSpec("chisel",      "chisel",      "go install github.com/jpillora/chisel@latest",  [4]),
    ToolSpec("dnscat2",     "dnscat2",     "gem install dnscat2",                            [4]),
    ToolSpec("frp",         "frp",         "Download: github.com/fatedier/frp/releases",    [4, 5]),
    ToolSpec("iodine",      "iodine",      "apt install iodine",                             [4]),
    ToolSpec("ligolo-ng",   "ligolo-ng",   "go install github.com/nicocha30/ligolo-ng/cmd/proxy@latest", [4, 5]),
    ToolSpec("proxychains4","proxychains4","apt install proxychains4",                       [4]),
    ToolSpec("socat",       "socat",       "apt install socat",                              [4]),
    ToolSpec("sshuttle",    "sshuttle",    "apt install sshuttle",                           [4]),

    # Remote access
    ToolSpec("evil-winrm",  "evil-winrm",  "gem install evil-winrm",                        [4]),
    ToolSpec("ftp",         "ftp",         "apt install ftp",                                [4]),
    ToolSpec("nc",          "nc",          "apt install netcat-openbsd",                     [4], "-h"),
    ToolSpec("ncat",        "ncat",        "apt install ncat",                               [4]),
    ToolSpec("pwncat-cs",   "pwncat-cs",   "pip3 install pwncat-cs",                         [4]),
    ToolSpec("ssh",         "ssh",         "apt install openssh-client",                     [4]),
    ToolSpec("xfreerdp",    "xfreerdp",    "apt install freerdp2-x11",                       [4]),

    # C2 frameworks
    ToolSpec("empire",      "empire",      "pip3 install powershell-empire",                 [1, 4, 5]),
    ToolSpec("sliver",      "sliver",      "Download: github.com/BishopFox/sliver/releases", [1, 4, 5]),

    # Impacket lateral movement
    ToolSpec("impacket-atexec",   "impacket-atexec",   "pip3 install impacket", [4]),
    ToolSpec("impacket-dcomexec", "impacket-dcomexec", "pip3 install impacket", [4]),
    ToolSpec("impacket-mssqlclient","impacket-mssqlclient","pip3 install impacket",[4]),
    ToolSpec("impacket-psexec",   "impacket-psexec",   "pip3 install impacket", [4]),
    ToolSpec("impacket-sambaPipe","impacket-sambaPipe","pip3 install impacket",  [4], "-h"),
    ToolSpec("impacket-services", "impacket-services", "pip3 install impacket",  [4, 5], "-h"),
    ToolSpec("impacket-smbexec",  "impacket-smbexec",  "pip3 install impacket",  [4]),
    ToolSpec("impacket-wmiexec",  "impacket-wmiexec",  "pip3 install impacket",  [4]),

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 5 — PERSISTENCE
    # ════════════════════════════════════════════════════════════════════════

    ToolSpec("impacket-reg",           "impacket-reg",          "pip3 install impacket", [5], "-h"),
    ToolSpec("impacket-registry-read", "impacket-registry-read","pip3 install impacket", [5, 6], "-h"),
    ToolSpec("impacket-wmipersist",    "impacket-wmipersist",   "pip3 install impacket", [5], "-h"),

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 6 — LOOT / CREDENTIAL EXTRACTION
    # ════════════════════════════════════════════════════════════════════════

    # Cracking
    ToolSpec("cewl",    "cewl",    "apt install cewl",    [6]),
    ToolSpec("crunch",  "crunch",  "apt install crunch",  [6]),
    ToolSpec("cupp",    "cupp",    "pip3 install cupp",   [6], "--help"),
    ToolSpec("hashcat", "hashcat", "apt install hashcat", [6]),
    ToolSpec("hashid",  "hashid",  "pip3 install hashid", [6]),
    ToolSpec("john",    "john",    "apt install john",    [6]),

    # Credential dumping
    ToolSpec("donpapi",  "donpapi",  "pip3 install donpapi",  [6], "--help"),
    ToolSpec("lsassy",   "lsassy",   "pip3 install lsassy",   [3, 6]),
    ToolSpec("pypykatz", "pypykatz", "pip3 install pypykatz", [6]),

    # Impacket loot
    ToolSpec("impacket-dpapi",    "impacket-dpapi",    "pip3 install impacket", [6], "-h"),
    ToolSpec("impacket-esentutl", "impacket-esentutl", "pip3 install impacket", [6], "-h"),
    ToolSpec("impacket-mimikatz", "impacket-mimikatz", "pip3 install impacket", [6], "-h"),
    ToolSpec("impacket-ntfs-read","impacket-ntfs-read","pip3 install impacket", [6], "-h"),

    # Forensics / analysis
    ToolSpec("autopsy",     "autopsy",    "apt install autopsy",   [6]),
    ToolSpec("binwalk",     "binwalk",    "apt install binwalk",   [6]),
    ToolSpec("strings",     "strings",   "apt install binutils",  [6]),
    ToolSpec("volatility3", "vol3",       "pip3 install volatility3",[6]),

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 7 — EVASION / PAYLOAD CRAFTING
    # ════════════════════════════════════════════════════════════════════════

    ToolSpec("checksec",  "checksec",  "pip3 install checksec",                                [7]),
    ToolSpec("donut",     "donut",     "go install github.com/TheWover/donut@latest",           [7]),
    ToolSpec("gdb",       "gdb",       "apt install gdb",                                       [7]),
    ToolSpec("mono",      "mono",      "apt install mono-complete",                              [3, 7]),
    ToolSpec("nim",       "nim",       "apt install nim",                                        [7]),
    ToolSpec("ROPgadget", "ROPgadget", "pip3 install ROPGadget",                                 [7]),
    ToolSpec("upx",       "upx",       "apt install upx-ucl",                                   [7]),
    ToolSpec("wine",      "wine",      "apt install wine",                                       [3, 7]),

    # ════════════════════════════════════════════════════════════════════════
    # UTILITIES — expected on any security workstation
    # ════════════════════════════════════════════════════════════════════════

    ToolSpec("curl",    "curl",    "apt install curl",          [0, 1, 2]),
    ToolSpec("dig",     "dig",     "apt install dnsutils",      [0]),
    ToolSpec("git",     "git",     "apt install git",           [0, 1, 2, 3, 4, 5, 6, 7]),
    ToolSpec("go",      "go",      "apt install golang",        [0, 2, 4, 7]),
    ToolSpec("jq",      "jq",      "apt install jq",            [0, 2, 6]),
    ToolSpec("openssl", "openssl", "apt install openssl",       [3, 7]),
    ToolSpec("perl",    "perl",    "apt install perl",          [0, 1, 2, 3, 4, 5, 6, 7]),
    ToolSpec("python2", "python2", "apt install python2",       [1, 3]),
    ToolSpec("python3", "python3", "apt install python3",       [0, 1, 2, 3, 4, 5, 6, 7]),
    ToolSpec("ruby",    "ruby",    "apt install ruby-full",     [4]),
    ToolSpec("screen",  "screen",  "apt install screen",        [0, 1, 2, 3, 4, 5, 6, 7]),
    ToolSpec("tmux",    "tmux",    "apt install tmux",          [0, 1, 2, 3, 4, 5, 6, 7]),
    ToolSpec("wget",    "wget",    "apt install wget",          [0, 1, 2]),
]

# De-duplicate by name (keep first occurrence) to guard against accidental dupes
_seen: set[str] = set()
_deduped: list[ToolSpec] = []
for _t in TOOL_CATALOG:
    if _t.name not in _seen:
        _seen.add(_t.name)
        _deduped.append(_t)
TOOL_CATALOG = _deduped


async def probe_tool(spec: ToolSpec) -> ToolResult:
    """Check if a single tool is available."""
    binary_path = shutil.which(spec.binary)
    if binary_path is None:
        return ToolResult(
            name=spec.name, binary=spec.binary, available=False,
            version=None, install_cmd=spec.install_cmd, phases=spec.phases,
        )

    version = None
    try:
        proc = await asyncio.create_subprocess_exec(
            spec.binary, spec.version_flag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        output = (stdout or stderr or b"").decode(errors="replace").strip()
        for line in output.splitlines():
            if any(c.isdigit() for c in line[:20]):
                version = line.strip()[:80]
                break
    except Exception:
        version = "installed"

    return ToolResult(
        name=spec.name, binary=spec.binary, available=True,
        version=version, install_cmd=spec.install_cmd, phases=spec.phases,
    )


async def probe_all_tools(concurrency: int = 8) -> list[ToolResult]:
    """Probe all tools with bounded concurrency."""
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_probe(spec: ToolSpec) -> ToolResult:
        async with semaphore:
            return await probe_tool(spec)

    return await asyncio.gather(*[bounded_probe(s) for s in TOOL_CATALOG])
