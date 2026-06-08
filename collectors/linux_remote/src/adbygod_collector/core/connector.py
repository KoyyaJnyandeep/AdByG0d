#!/usr/bin/env python3
"""
AdByG0d - Connection Manager
Handles LDAP, SMB, and Kerberos connections to the target domain.
"""

import ssl

from .banner import info, success, error, warning
from .ldap_values import first_value

try:
    from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS, Tls, SUBTREE, ALL_ATTRIBUTES
    from ldap3.core.exceptions import LDAPException
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

try:
    from impacket.smbconnection import SMBConnection
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


class ADConnector:
    """Manages connections to an Active Directory environment."""

    def __init__(self, target, domain, username=None, password=None,
                 hashes=None, dc_ip=None, use_ssl=False, timeout=10):
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.lmhash = ""
        self.nthash = ""
        self.dc_ip = dc_ip or target
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.base_dn = None
        self.ldap_conn = None
        self.smb_conn = None
        self.connected = False

        if hashes:
            parts = hashes.split(":")
            if len(parts) == 2:
                self.lmhash, self.nthash = parts
            else:
                self.nthash = parts[0]

        # Build base DN from domain
        self.base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    def connect_ldap(self):
        """Establish LDAP connection. Tries NTLM/LDAPS, then Kerberos (GSSAPI) as fallback.
        Channel binding (LdapEnforceChannelBinding=2) blocks NTLM over plain LDAP;
        Kerberos/GSSAPI is exempt and works against hardened DCs."""
        if not HAS_LDAP3:
            error("ldap3 library not installed. Run: pip install ldap3")
            return False

        strategies = []

        if self.username and (self.password or self.nthash):
            ntlm_user = f"{self.domain}\\{self.username}"
            ntlm_pass = self.password if self.password else f"{self.lmhash}:{self.nthash}"
            # 1. NTLM over LDAPS (636) — works if cert chain OK or CERT_NONE
            strategies.append({"port": 636, "use_ssl": True,  "auth": NTLM,  "user": ntlm_user, "pass": ntlm_pass})
            # 2. Kerberos/GSSAPI over LDAP (389) — exempt from channel binding requirement
            strategies.append({"port": 389, "use_ssl": False, "auth": SASL,  "user": None,      "pass": None,    "sasl_mech": KERBEROS})
            # 3. NTLM over plain LDAP (389) — blocked by channel binding but try anyway
            strategies.append({"port": 389, "use_ssl": False, "auth": NTLM,  "user": ntlm_user, "pass": ntlm_pass})
        else:
            strategies.append({"port": 389, "use_ssl": False, "auth": None,  "user": None,      "pass": None})

        for s in strategies:
            try:
                tls_config = Tls(validate=ssl.CERT_NONE) if s["use_ssl"] else None
                server = Server(
                    self.dc_ip,
                    port=s["port"],
                    use_ssl=s["use_ssl"],
                    tls=tls_config,
                    get_info=ALL,
                    connect_timeout=self.timeout
                )

                if s["auth"] == SASL:
                    conn = Connection(
                        server,
                        authentication=SASL,
                        sasl_mechanism=s["sasl_mech"],
                        auto_referrals=False,
                        receive_timeout=self.timeout
                    )
                elif s["auth"] == NTLM:
                    conn = Connection(
                        server,
                        user=s["user"],
                        password=s["pass"],
                        authentication=NTLM,
                        auto_referrals=False,
                        receive_timeout=self.timeout
                    )
                else:
                    conn = Connection(server, auto_referrals=False, receive_timeout=self.timeout)

                if conn.bind():
                    self.ldap_conn = conn
                    self.connected = True
                    proto = "LDAPS" if s["use_ssl"] else "LDAP"
                    auth_name = {NTLM: "NTLM", SASL: "Kerberos/GSSAPI", None: "Anonymous"}.get(s["auth"], str(s["auth"]))
                    success(f"LDAP connected to {self.dc_ip}:{s['port']} via {proto}/{auth_name}")

                    if server.info:
                        if server.info.other.get('defaultNamingContext'):
                            self.base_dn = str(first_value(server.info.other.get('defaultNamingContext'), self.base_dn))
                            info(f"Base DN: {self.base_dn}")
                        if server.info.other.get('dnsHostName'):
                            info(f"DC Hostname: {first_value(server.info.other.get('dnsHostName'), 'unknown')}")
                        if server.info.other.get('forestFunctionality'):
                            fl = str(first_value(server.info.other.get('forestFunctionality'), ""))
                            fl_map = {'0':'Win2000','1':'Win2003-Interim','2':'Win2003','3':'Win2008',
                                      '4':'Win2008R2','5':'Win2012','6':'Win2012R2','7':'Win2016'}
                            info(f"Forest Level: {fl_map.get(fl, fl)}")
                    return True
                else:
                    proto = "LDAPS" if s["use_ssl"] else "LDAP"
                    auth_name = {NTLM: "NTLM", SASL: "Kerberos", None: "Anonymous"}.get(s["auth"], "?")
                    warning(f"{proto}/{auth_name} bind failed: {conn.result.get('description','?')} [{conn.result.get('message','')[:60]}]")
            except Exception as e:
                warning(f"Strategy {s['port']}/{'SSL' if s['use_ssl'] else 'plain'} error: {str(e)[:80]}")
                continue

        error("All LDAP connection strategies exhausted — could not bind")
        return False

    def connect_smb(self):
        """Establish SMB connection."""
        if not HAS_IMPACKET:
            error("impacket library not installed. Run: pip install impacket")
            return False

        try:
            self.smb_conn = SMBConnection(self.dc_ip, self.dc_ip, timeout=self.timeout)

            if self.username:
                if self.nthash:
                    self.smb_conn.login(
                        self.username, '',
                        self.domain,
                        lmhash=self.lmhash,
                        nthash=self.nthash
                    )
                else:
                    self.smb_conn.login(self.username, self.password, self.domain)
            else:
                # Null session
                self.smb_conn.login('', '')

            success(f"SMB connection established to {self.dc_ip}")
            info(f"SMB Dialect: {self.smb_conn.getDialect()}")
            return True

        except Exception as e:
            error(f"SMB connection failed: {str(e)}")
            return False

    def ldap_search(self, search_filter, attributes=None, search_base=None, size_limit=0):
        """Perform an LDAP search and return entries."""
        if not self.ldap_conn:
            return []

        base = search_base or self.base_dn
        attrs = attributes or [ALL_ATTRIBUTES]

        try:
            self.ldap_conn.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attrs,
                size_limit=size_limit
            )
            return self.ldap_conn.entries
        except LDAPException as e:
            error(f"LDAP search failed: {str(e)}")
            return []

    def ldap_search_raw(self, search_filter, attributes=None, search_base=None, size_limit=0):
        """Perform LDAP search and return raw response entries."""
        if not self.ldap_conn:
            return []

        base = search_base or self.base_dn
        attrs = attributes or ['*']

        try:
            self.ldap_conn.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attrs,
                size_limit=size_limit
            )
            return self.ldap_conn.response
        except LDAPException as e:
            error(f"LDAP search failed: {str(e)}")
            return []

    def close(self):
        """Close all connections."""
        if self.ldap_conn:
            try:
                self.ldap_conn.unbind()
            except Exception:
                pass
        if self.smb_conn:
            try:
                self.smb_conn.close()
            except Exception:
                pass
