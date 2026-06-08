"""Import all expert modules to trigger @register() decorators."""
from . import (
    kerberos,
    acl,
    dcsync,
    ntlm_relay,
    trust,
    adcs,
    shadow_credentials,
    gpo_abuse,
    laps_exposure,
    delegation,
    password_policy,
    sid_history,
    maq_rbcd,
    recon_exposure,
    pre2k_exposure,
    timeroast_exposure,
    wsus_exposure,
    network_posture,
    user_accounts,
    service_accounts,
    domain_config,
)

__all__ = [
    "kerberos", "acl", "dcsync", "ntlm_relay", "trust",
    "adcs", "shadow_credentials", "gpo_abuse", "laps_exposure",
    "delegation", "password_policy", "sid_history", "maq_rbcd",
    "recon_exposure", "pre2k_exposure", "timeroast_exposure", "wsus_exposure",
    "network_posture", "user_accounts", "service_accounts", "domain_config",
]
