from __future__ import annotations

import random
import uuid
from dataclasses import dataclass


@dataclass
class SyntheticADConfig:
    # Scale
    user_count: int = 500
    computer_count: int = 200
    dc_count: int = 2
    domain_count: int = 1
    ou_depth: int = 3
    group_count: int = 50

    # Kerberos attack surface
    asrep_pct: float = 0.05          # % users with PreAuthNotRequired
    kerberoastable_pct: float = 0.08  # % users with SPN

    # ACL misconfigurations
    acl_misconfiguration_pct: float = 0.10

    # LAPS
    laps_coverage_pct: float = 0.60

    # Delegation
    unconstrained_delegation_pct: float = 0.02

    # ADCS
    adcs_templates: int = 5
    esc1_templates: int = 1
    ca_count: int = 1

    # Shadow Credentials
    shadow_credential_write_edges: int = 2

    # GPO
    gpo_count: int = 10
    gpo_write_edges: int = 3

    # MAQ/RBCD
    maq_value: int = 10
    rbcd_edges: int = 2

    # SID History
    sid_history_count: int = 5

    # Password Policy
    password_policy_minlength: int = 8
    password_policy_complexity: bool = True
    password_lockout_threshold: int = 0  # 0 = no lockout

    # Constrained Delegation
    constrained_delegation_count: int = 3

    description: str = ""


class SyntheticADGenerator:
    def generate(self, config: SyntheticADConfig):
        """Generate a ValidationAssessmentContext from synthetic config."""
        from adbygod_api.core.validation.context import ValidationAssessmentContext

        rng = random.Random(42)  # Deterministic for reproducibility

        domain_name = f"synth{rng.randint(100,999)}.lab"
        assessment_id = f"synth-{uuid.uuid4().hex[:8]}"

        # Generate entities
        users = self._generate_users(config, rng)
        computers = self._generate_computers(config, rng)
        dcs = self._generate_dcs(config, rng)
        groups = self._generate_groups(config, rng)
        ous = self._generate_ous(config, rng)
        all_entities = users + computers + dcs + groups + ous

        # Generate edges
        edges = self._generate_edges(config, rng, users, computers, dcs, groups, ous)

        # Generate findings
        findings = self._generate_findings(config, rng, users, computers, dcs)

        # Generate certificate templates
        cert_templates = self._generate_cert_templates(config, rng)

        # Generate GPO objects
        gpos = self._generate_gpos(config, rng, ous)

        # LAPS computers
        laps_comps = computers[:int(len(computers) * config.laps_coverage_pct)]
        laps_computer_ids = [c['id'] for c in laps_comps]

        # Shadow credential edges
        shadow_edges = self._generate_shadow_edges(config, rng, users, computers, dcs)

        # SID history entities
        sid_entities = self._generate_sid_history(config, rng, users)

        # Password policy
        policy_objs = [
            {
                'is_default': True,
                'min_length': config.password_policy_minlength,
                'max_age_days': 90,
                'complexity_enabled': config.password_policy_complexity,
                'lockout_threshold': config.password_lockout_threshold,
                'applies_to': 'domain',
            }
        ]

        # Delegation
        unconstrained_count = max(1, int(len(computers) * config.unconstrained_delegation_pct))
        unconstrained_ids = [c['id'] for c in computers[:unconstrained_count]]

        constrained_delegation = [
            {'entity_id': u['id'], 'allowed_spns': [f'ldap/dc01.{domain_name}', 'cifs/fileserver']}
            for u in users[:config.constrained_delegation_count]
        ]

        rbcd_edges = self._generate_rbcd_edges(config, rng, computers)

        # Spray candidates: enabled users with passwordNeverExpires or old password
        spray_cands = rng.sample(users, min(int(len(users) * 0.15), len(users)))

        # Tier-0 entities: Domain Admins, Enterprise Admins, krbtgt, DCs
        tier0_ids = [dc['id'] for dc in dcs] + [g['id'] for g in groups if 'admin' in g['name'].lower()]

        ctx = ValidationAssessmentContext(
            assessment_id=assessment_id,
            domain=domain_name,
            collection_mode="SYNTHETIC",
            entities=all_entities,
            edges=edges,
            findings=findings,
            # New rich fields
            computer_count=len(computers) + len(dcs),
            dc_count=len(dcs),
            domain_count=config.domain_count,
            ou_count=len(ous),
            tier0_entities=tier0_ids,
            certificate_templates=cert_templates,
            gpo_objects=gpos,
            laps_computers=laps_computer_ids,
            shadow_credential_edges=shadow_edges,
            sid_history_entities=sid_entities,
            password_policy_objects=policy_objs,
            maq_value=config.maq_value,
            unconstrained_delegation=unconstrained_ids,
            constrained_delegation=constrained_delegation,
            rbcd_edges=rbcd_edges,
            spray_candidates=spray_cands,
        )
        # Patch user_count if it exists
        if hasattr(ctx, 'user_count'):
            ctx.user_count = len(users)

        return ctx

    def _generate_users(self, config, rng) -> list[dict]:
        users = []
        for i in range(config.user_count):
            is_asrep = rng.random() < config.asrep_pct
            is_kerb = rng.random() < config.kerberoastable_pct
            name = f"user_{i:04d}"
            if i == 0:
                name = "krbtgt"
            elif i < 5:
                name = f"svc_{['sql', 'backup', 'iis', 'exchange', 'mgmt'][i-1]}"
            users.append({
                'id': str(uuid.uuid4()),
                'name': name,
                'type': 'User',
                'properties': {
                    'enabled': True,
                    'dontrequirepreauth': is_asrep,
                    'hasspn': is_kerb,
                    'passwordneverexpires': rng.random() < 0.15,
                    'admincount': i < 3,
                },
                'is_enabled': True,
            })
        # Add DA
        users.append({
            'id': str(uuid.uuid4()),
            'name': 'Domain Admin',
            'type': 'User',
            'properties': {'enabled': True, 'admincount': True},
            'is_enabled': True,
        })
        return users

    def _generate_computers(self, config, rng) -> list[dict]:
        computers = []
        for i in range(config.computer_count):
            computers.append({
                'id': str(uuid.uuid4()),
                'name': f"WS{i:04d}",
                'type': 'Computer',
                'properties': {
                    'enabled': True,
                    'isdc': False,
                    'operatingsystem': rng.choice(['Windows 10', 'Windows 11', 'Windows Server 2019', 'Windows Server 2022']),
                },
            })
        return computers

    def _generate_dcs(self, config, rng) -> list[dict]:
        dcs = []
        for i in range(config.dc_count):
            dcs.append({
                'id': str(uuid.uuid4()),
                'name': f"DC{i+1:02d}",
                'type': 'Computer',
                'properties': {
                    'enabled': True,
                    'isdc': True,
                    'operatingsystem': 'Windows Server 2022',
                },
            })
        return dcs

    def _generate_groups(self, config, rng) -> list[dict]:
        groups = []
        standard_groups = [
            'Domain Admins', 'Enterprise Admins', 'Schema Admins',
            'Domain Users', 'Domain Computers', 'Protected Users',
            'Remote Desktop Users', 'Backup Operators', 'Account Operators',
        ]
        for gname in standard_groups:
            groups.append({
                'id': str(uuid.uuid4()),
                'name': gname,
                'type': 'Group',
                'properties': {'admincount': 'admin' in gname.lower()},
            })
        for i in range(config.group_count - len(standard_groups)):
            groups.append({
                'id': str(uuid.uuid4()),
                'name': f"group_{i:03d}",
                'type': 'Group',
                'properties': {},
            })
        return groups

    def _generate_ous(self, config, rng) -> list[dict]:
        ous = []
        ou_names = ['Workstations', 'Servers', 'Users', 'ServiceAccounts', 'DMZ', 'Laptops']
        for name in ou_names:
            ous.append({
                'id': str(uuid.uuid4()),
                'name': name,
                'type': 'OU',
                'properties': {},
            })
        return ous

    def _generate_edges(self, config, rng, users, computers, dcs, groups, ous) -> list[dict]:
        edges = []
        all_computers = computers + dcs

        # ACL edges (misconfigurations)
        acl_count = int(len(users) * config.acl_misconfiguration_pct)
        priv_targets = [g for g in groups if 'admin' in g['name'].lower()][:3] + dcs[:2]
        acl_types = ['GenericAll', 'WriteDACL', 'WriteOwner', 'GenericWrite']
        for i in range(acl_count):
            if not priv_targets:
                break
            edges.append({
                'id': str(uuid.uuid4()),
                'relationship_type': rng.choice(acl_types),
                'source_id': users[i % len(users)]['id'],
                'source_name': users[i % len(users)]['name'],
                'target_id': priv_targets[i % len(priv_targets)]['id'],
                'target_name': priv_targets[i % len(priv_targets)]['name'],
                'target_label': 'Group',
            })

        # GPO write edges
        for i in range(config.gpo_write_edges):
            if not ous:
                break
            edges.append({
                'id': str(uuid.uuid4()),
                'relationship_type': rng.choice(['WriteDACL', 'WriteProperty', 'GenericAll']),
                'source_id': users[i % len(users)]['id'],
                'source_name': users[i % len(users)]['name'],
                'target_id': ous[i % len(ous)]['id'],
                'target_name': f"GPO_{i}",
                'target_label': 'GPO',
            })

        # LAPS read edges
        laps_comps = all_computers[:int(len(all_computers) * (1 - config.laps_coverage_pct))]
        for i, comp in enumerate(laps_comps[:10]):
            edges.append({
                'id': str(uuid.uuid4()),
                'relationship_type': 'ReadLAPSPassword',
                'source_id': users[i % len(users)]['id'],
                'source_name': users[i % len(users)]['name'],
                'target_id': comp['id'],
                'target_name': comp['name'],
                'target_label': 'Computer',
            })

        # DCSync edges
        if dcs:
            for i in range(3):
                edges.append({
                    'id': str(uuid.uuid4()),
                    'relationship_type': 'GetChangesAll',
                    'source_id': users[i]['id'],
                    'source_name': users[i]['name'],
                    'target_id': dcs[0]['id'],
                    'target_name': dcs[0]['name'],
                    'target_label': 'DomainController',
                })

        return edges

    def _generate_findings(self, config, rng, users, computers, dcs) -> list[dict]:
        findings = []

        # AS-REP roast findings
        asrep_users = [u for u in users if u['properties'].get('dontrequirepreauth', False)]
        for u in asrep_users[:5]:
            findings.append({
                'id': str(uuid.uuid4()),
                'title': 'AS-REP Roastable Account',
                'category': 'kerberos',
                'severity': 'HIGH',
                'description': f"Account {u['name']} does not require Kerberos pre-authentication",
                'entity_id': u['id'],
                'entity_name': u['name'],
            })

        # Kerberoastable findings
        kerb_users = [u for u in users if u['properties'].get('hasspn', False)]
        for u in kerb_users[:5]:
            findings.append({
                'id': str(uuid.uuid4()),
                'title': 'Kerberoastable SPN Account',
                'category': 'kerberos',
                'severity': 'MEDIUM',
                'description': f"Account {u['name']} has an SPN and is vulnerable to Kerberoasting",
                'entity_id': u['id'],
                'entity_name': u['name'],
            })

        # ADCS ESC1 findings
        for i in range(config.esc1_templates):
            findings.append({
                'id': str(uuid.uuid4()),
                'title': 'ADCS ESC1 Vulnerable Template',
                'category': 'adcs',
                'severity': 'CRITICAL',
                'description': f"Certificate template ESC1_Template_{i} allows enrollee-supplied SAN",
            })

        # Password policy findings
        if config.password_policy_minlength < 12:
            findings.append({
                'id': str(uuid.uuid4()),
                'title': 'Weak Password Policy',
                'category': 'password_policy',
                'severity': 'MEDIUM',
                'description': f"Minimum password length is {config.password_policy_minlength} (recommended: 14+)",
            })

        if config.password_lockout_threshold == 0:
            findings.append({
                'id': str(uuid.uuid4()),
                'title': 'No Account Lockout Policy',
                'category': 'password_policy',
                'severity': 'HIGH',
                'description': "No account lockout threshold configured — enables unlimited password spray",
            })

        # SID history findings
        for i in range(min(config.sid_history_count, 5)):
            findings.append({
                'id': str(uuid.uuid4()),
                'title': 'SID History Detected',
                'category': 'sid_history',
                'severity': 'HIGH' if i < 2 else 'MEDIUM',
                'description': f"Account {users[i]['name']} has sIDHistory with privileged SID" if i < 2 else f"Account {users[i]['name']} has sIDHistory attribute",
                'entity_id': users[i]['id'],
            })

        # DCSync findings
        if dcs:
            findings.append({
                'id': str(uuid.uuid4()),
                'title': 'DCSync Rights Detected',
                'category': 'dcsync',
                'severity': 'CRITICAL',
                'description': "3 accounts have replication rights (GetChanges/GetChangesAll) on the domain",
            })

        return findings

    def _generate_cert_templates(self, config, rng) -> list[dict]:
        templates = []
        for i in range(config.adcs_templates):
            is_esc1 = i < config.esc1_templates
            templates.append({
                'id': str(uuid.uuid4()),
                'name': f"Template_{i:02d}{'_ESC1' if is_esc1 else ''}",
                'esc1_vulnerable': is_esc1,
                'enrollee_supplies_subject': is_esc1,
                'low_priv_enrollment': is_esc1,
                'enabled': True,
            })
        return templates

    def _generate_gpos(self, config, rng, ous) -> list[dict]:
        gpos = []
        for i in range(config.gpo_count):
            writable = i < config.gpo_write_edges
            gpos.append({
                'id': str(uuid.uuid4()),
                'name': f"GPO_{i:03d}",
                'linked_ou': ous[i % len(ous)]['name'] if ous else 'Default',
                'writable_by_non_admin': writable,
            })
        return gpos

    def _generate_shadow_edges(self, config, rng, users, computers, dcs) -> list[dict]:
        edges = []
        targets = users[:5] + dcs[:2]
        for i in range(config.shadow_credential_write_edges):
            if i >= len(targets):
                break
            edges.append({
                'id': str(uuid.uuid4()),
                'source_id': users[i % len(users)]['id'],
                'source_name': users[i % len(users)]['name'],
                'target_id': targets[i]['id'],
                'target_name': targets[i]['name'],
                'relationship_type': 'WriteProperty',
                'attribute': 'msDS-KeyCredentialLink',
            })
        return edges

    def _generate_sid_history(self, config, rng, users) -> list[dict]:
        sid_entities = []
        for i in range(min(config.sid_history_count, len(users))):
            is_priv = i < 2  # First 2 have privileged SIDs
            sid_entities.append({
                'entity_id': users[i]['id'],
                'name': users[i]['name'],
                'sid_history': [f"S-1-5-21-{rng.randint(1000000,9999999)}-{rng.randint(1000,9999)}-{513 if is_priv else rng.randint(1000,9999)}"],
                'resolved_sids': ['Domain Admins'] if is_priv else [f'Legacy_Group_{i}'],
            })
        return sid_entities

    def _generate_rbcd_edges(self, config, rng, computers) -> list[dict]:
        edges = []
        for i in range(config.rbcd_edges):
            if i >= len(computers):
                break
            edges.append({
                'id': str(uuid.uuid4()),
                'target_id': computers[i]['id'],
                'target_name': computers[i]['name'],
                'attribute': 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                'source_name': f'attacker_computer_{i}',
            })
        return edges
