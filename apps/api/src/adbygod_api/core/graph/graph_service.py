from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx

from adbygod_api.core.dcsync_principals import classify_dcsync_principal

log = logging.getLogger(__name__)

EDGE_RISK: Dict[str, float] = {
    "GENERIC_ALL": 1.00, "OWNS": 0.95,
    "WRITE_DACL": 0.90, "WRITE_OWNER": 0.88,
    "FORCE_CHANGE_PASSWORD": 0.85, "DCSYNC": 1.00,
    "ALLOWED_TO_ACT": 0.80, "ALLOWED_TO_DELEGATE": 0.75,
    "ADD_MEMBER": 0.70, "MEMBER_OF": 0.50,
    "ADMIN_TO": 0.85, "LOCAL_ADMIN": 0.80,
    "CAN_RDP": 0.45, "CAN_WINRM": 0.50,
    "HAS_SPN": 0.40, "CAN_ENROLL": 0.55,
    "CONTAINS": 0.20, "APPLIES_GPO": 0.35,
    "TRUSTS": 0.60, "HAS_CONTROL": 0.70,
    # lateral movement
    "PASS_THE_HASH": 0.85, "PASS_THE_TICKET": 0.85,
    "PASS_THE_CERT": 0.90, "OVERPASS_THE_HASH": 0.82,
    "COERCION": 0.75, "REMOTE_EXEC": 0.80,
    "READ_LAPS_PASSWORD": 0.78, "READ_GMSA_PASSWORD": 0.78,
    "ADD_KEY_CREDENTIAL_LINK": 0.88, "S4U2SELF": 0.80,
    "GPO_EXEC": 0.85, "DCOM_EXEC": 0.70, "WMI_EXEC": 0.70,
    "SCM_EXEC": 0.82, "NAMED_PIPE_IMPERSONATE": 0.72,
    "SEIMPERSONATE": 0.78, "RDP_HIJACK": 0.75,
    "ADCS_RELAY": 0.95, "PETITPOTAM": 0.85,
    "PRINTSPOOLER": 0.80, "SHADOWCOERCE": 0.78,
    "DFSCOERCE": 0.78, "WEBDAV_COERCE": 0.72,
    "MSSQL_LINKED": 0.68, "MSSQL_CLR": 0.82,
    "MSSQL_UNC": 0.72, "SCCM_NAA": 0.80,
    "AADCONNECT_SYNC": 1.00, "DNS_ADMIN_EXEC": 0.90,
    "ADIDNS_WRITE": 0.65, "REGISTRY_EXEC": 0.70,
    "SQL_ADMIN": 0.72, "NTLM_RELAY": 0.82,
    "KERBEROS_RELAY": 0.80, "POISONING": 0.70,
    "GOLDEN_TICKET": 1.00, "EXTRASID": 0.95,
    "SID_HISTORY": 0.90, "CVE_CHAIN": 0.85,
    "MACHINE_ACCOUNT": 0.65, "ADCS_ESC1": 0.92,
    "ADCS_ESC8": 0.95, "ADCS_ESC15": 0.88,
    "NTLM_CAPTURE": 0.72, "ADIDNS_CAN_WRITE": 0.65,
}


def _safe_float(value: Any, default: float = 0.5) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


CONTROL_EDGES: Set[str] = {
    "GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS",
    "FORCE_CHANGE_PASSWORD", "DCSYNC", "ADMIN_TO", "LOCAL_ADMIN",
    "ADD_MEMBER", "ALLOWED_TO_ACT", "ALLOWED_TO_DELEGATE",
}

TRAVERSAL_EDGES: Set[str] = {"MEMBER_OF", "CONTAINS", "APPLIES_GPO"}

CREDENTIAL_EDGES: Set[str] = {
    "DCSYNC", "FORCE_CHANGE_PASSWORD", "ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT",
}

HVT_TYPES: Set[str] = {"DC", "CA", "DOMAIN", "FOREST"}

HVT_SAM_PATTERNS: Tuple[str, ...] = (
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "domain controllers", "read-only domain controllers", "group policy creator owners",
    "dnsupdateproxy", "account operators", "backup operators", "print operators",
    "server operators", "replicator", "krbtgt",
)

# prevent combinatorial explosion
_MAX_SIMPLE_PATH_ITERS: int = 50_000


@dataclass
class PathStep:
    node_id: str
    node_label: str
    node_type: str
    tier: Optional[int]
    is_crown_jewel: bool
    edge_type: Optional[str] = None
    edge_risk: float = 0.0
    edge_provenance: Optional[str] = None
    explanation: str = ""


@dataclass
class AttackPath:
    source_id: str
    target_id: str
    source_label: str
    target_label: str
    hop_count: int
    path_score: float
    risk_level: str
    steps: List[PathStep] = field(default_factory=list)
    node_ids: List[str] = field(default_factory=list)
    edge_types: List[str] = field(default_factory=list)
    involves_credential_access: bool = False
    involves_delegation: bool = False
    involves_adcs: bool = False
    crosses_trust: bool = False
    explanation: str = ""
    confidence: float = 1.0

    # backward-compatible attribute name
    @property
    def path(self) -> List[str]:
        return self.node_ids

    @property
    def path_steps(self) -> List[PathStep]:
        return self.steps


@dataclass
class PathResult:
    source_id: str
    target_id: str
    path: List[str]
    edge_types: List[str]
    hop_count: int
    path_score: float
    explanation: str


@dataclass
class ShadowAdmin:
    entity_id: str
    entity_label: str
    entity_type: str
    control_paths: List[str]
    targets: List[str]
    risk_score: float


@dataclass
class DelegationChain:
    entity_id: str
    entity_label: str
    entity_type: str
    delegation_type: str
    delegation_targets: List[str]
    can_reach_tier0: bool
    tier0_targets: List[str]
    risk_score: float


@dataclass
class ADCSPath:
    template_name: str
    ca_name: str
    esc_type: str
    enrolling_principals: List[str]
    risk_score: float
    description: str
    affected_paths_to_tier0: int = 0


@dataclass
class ChokePoint:
    node_id: str
    node_label: str
    node_type: str
    attack_paths_through: int
    is_articulation_point: bool
    betweenness_score: float
    remediation_impact: float


@dataclass
class GraphBlastRadiusResult:
    total_non_tier0_nodes: int
    reachable_count: int
    reach_pct: float
    tier0_reached: int
    top_exposed: List[Dict[str, Any]]


@dataclass
class DomainDominanceResult:
    domain: str
    tier0_total: int
    tier0_reachable_from_source: int
    dominance_pct: float
    owned_paths: int
    critical_path: Optional[AttackPath]


@dataclass
class GraphStats:
    node_count: int
    edge_count: int
    tier0_count: int
    enabled_user_count: int
    computer_count: int
    group_count: int
    ca_count: int
    domain_count: int
    edge_type_breakdown: Dict[str, int]
    avg_degree: float
    density: float
    is_connected: bool
    component_count: int


def _build_meta_from_orm(ent, attrs: dict) -> dict:
    return {
        "type":               ent.entity_type.value if ent.entity_type else "UNKNOWN",
        "tier":               ent.tier,
        "is_crown_jewel":     bool(ent.is_crown_jewel),
        "sam_account_name":   ent.sam_account_name,
        "display_name":       ent.display_name,
        "distinguished_name": ent.distinguished_name,
        "object_sid":         ent.object_sid,
        "dns_hostname":       ent.dns_hostname,
        "domain":             ent.domain,
        "is_enabled":         bool(ent.is_enabled) if ent.is_enabled is not None else True,
        "is_admin_count":     bool(ent.is_admin_count),
        "is_sensitive":       bool(ent.is_sensitive) if hasattr(ent, "is_sensitive") else False,
        "is_protected_user":  bool(ent.is_protected_user) if hasattr(ent, "is_protected_user") else False,
        "uac_dont_req_preauth":      bool(attrs.get("uac_dont_require_preauth", attrs.get("dont_require_preauth", False))),
        "uac_trusted_for_deleg":     bool(attrs.get("uac_trusted_for_delegation", attrs.get("trusted_for_delegation", False))),
        "uac_trusted_to_auth_deleg": bool(attrs.get("uac_trusted_to_auth_for_delegation", False)),
        "uac_passwd_notreqd":        bool(attrs.get("uac_passwd_notreqd", attrs.get("passwd_notreqd", False))),
        "has_spn":            bool(attrs.get("has_spn", False)),
        "laps_enabled":       bool(attrs.get("laps_enabled", False)),
        "gmsa":               ent.entity_type.value == "GMSA" if ent.entity_type else False,
        "business_tags":      list(ent.business_tags) if ent.business_tags else [],
        "attributes":         attrs,
    }


def _build_meta_from_dict(ent: dict, attrs: dict) -> dict:
    return {
        "type":               str(ent.get("entity_type", "UNKNOWN")).upper(),
        "tier":               ent.get("tier"),
        "is_crown_jewel":     bool(ent.get("is_crown_jewel", False)),
        "sam_account_name":   ent.get("sam_account_name"),
        "display_name":       ent.get("display_name"),
        "distinguished_name": ent.get("distinguished_name"),
        "object_sid":         ent.get("object_sid"),
        "dns_hostname":       ent.get("dns_hostname"),
        "domain":             ent.get("domain"),
        "is_enabled":         bool(ent.get("is_enabled", True)),
        "is_admin_count":     bool(ent.get("is_admin_count", False)),
        "is_sensitive":       bool(ent.get("is_sensitive", False)),
        "is_protected_user":  bool(ent.get("is_protected_user", False)),
        "uac_dont_req_preauth":      bool(attrs.get("uac_dont_require_preauth", False)),
        "uac_trusted_for_deleg":     bool(attrs.get("uac_trusted_for_delegation", False)),
        "uac_trusted_to_auth_deleg": bool(attrs.get("uac_trusted_to_auth_for_delegation", False)),
        "uac_passwd_notreqd":        bool(attrs.get("uac_passwd_notreqd", False)),
        "has_spn":            bool(attrs.get("has_spn", False)),
        "laps_enabled":       bool(attrs.get("laps_enabled", False)),
        "gmsa":               str(ent.get("entity_type", "")).upper() == "GMSA",
        "business_tags":      list(ent.get("business_tags", [])),
        "attributes":         attrs,
    }


class ADGraphAnalyzer:

    def __init__(self) -> None:
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self.entity_meta: Dict[str, dict] = {}
        self.edge_meta: Dict[Tuple[str, str, str], dict] = {}
        self.community_map: dict = {}
        self._tier0: Set[str] = set()
        self._hvt: Set[str] = set()
        self._owned: Set[str] = set()
        self._group_members: Dict[str, Set[str]] = {}
        self._member_of: Dict[str, Set[str]] = {}
        self._sam_index: Dict[str, str] = {}
        self._dn_index: Dict[str, str] = {}
        self._sid_index: Dict[str, str] = {}
        self._domain_index: Dict[str, Set[str]] = {}
        self._edge_type_index: Dict[str, List[Tuple[str, str]]] = {}
        self._cert_templates: List[dict] = []
        self._indexes_valid: bool = False

    def load_from_db(self, entities: Iterable, edges: Iterable) -> None:
        self.graph.clear()
        self.entity_meta.clear()
        self.edge_meta.clear()
        self._cert_templates.clear()
        self._owned.clear()

        for ent in entities:
            eid = str(ent.id)
            attrs = ent.attributes or {}
            meta = _build_meta_from_orm(ent, attrs)
            self.entity_meta[eid] = meta
            self.graph.add_node(eid, **meta)

        for edge in edges:
            src = str(edge.source_id)
            tgt = str(edge.target_id)
            etype = edge.edge_type.value if edge.edge_type else "UNKNOWN"
            rw = _safe_float(edge.risk_weight, EDGE_RISK.get(etype, 0.5))
            attrs = edge.attributes or {}
            prov = edge.provenance or ""
            edge_id = str(edge.id)
            confidence = float(getattr(edge, 'edge_confidence', 1.0) or 1.0)
            prov_type = getattr(edge, 'edge_provenance_type', 'collected') or 'collected'
            self.graph.add_edge(src, tgt, key=edge_id,
                                edge_type=etype, risk_weight=rw, provenance=prov,
                                edge_confidence=confidence, edge_provenance_type=prov_type,
                                attributes=attrs)
            self.edge_meta[(src, tgt, edge_id)] = {
                "type": etype, "risk_weight": rw, "provenance": prov,
                "edge_confidence": confidence, "edge_provenance_type": prov_type,
                "attributes": attrs,
            }

        self._rebuild_indexes()

    def load_from_dicts(
        self,
        entities: List[dict],
        edges: List[dict],
        cert_templates: Optional[List[dict]] = None,
    ) -> None:
        self.graph.clear()
        self.entity_meta.clear()
        self.edge_meta.clear()
        self._cert_templates = list(cert_templates or [])
        self._owned.clear()

        for ent in entities:
            eid = str(ent.get("id", ""))
            if not eid:
                continue
            attrs = ent.get("attributes", {}) or {}
            meta = _build_meta_from_dict(ent, attrs)
            self.entity_meta[eid] = meta
            self.graph.add_node(eid, **meta)

        for edge in edges:
            src = str(edge.get("source_id", ""))
            tgt = str(edge.get("target_id", ""))
            if not src or not tgt:
                continue
            etype = str(edge.get("edge_type", "HAS_CONTROL")).upper()
            rw = _safe_float(edge.get("risk_weight"), EDGE_RISK.get(etype, 0.5))
            attrs = edge.get("attributes", {}) or {}
            prov = edge.get("provenance", "")
            edge_id = str(edge.get("id", f"{src}__{tgt}__{etype}"))
            confidence = float(edge.get("edge_confidence", 1.0))
            prov_type = edge.get("edge_provenance_type", "collected")
            self.graph.add_edge(src, tgt, key=edge_id,
                                edge_type=etype, risk_weight=rw, provenance=prov,
                                edge_confidence=confidence, edge_provenance_type=prov_type,
                                attributes=attrs)
            self.edge_meta[(src, tgt, edge_id)] = {
                "type": etype, "risk_weight": rw, "provenance": prov,
                "edge_confidence": confidence, "edge_provenance_type": prov_type,
                "attributes": attrs,
            }

        self._rebuild_indexes()

    def set_owned_nodes(self, node_ids: Iterable[str]) -> None:
        self._owned = {str(nid) for nid in node_ids}

    def add_cert_templates(self, templates: List[dict]) -> None:
        self._cert_templates = list(templates)

    def _rebuild_indexes(self) -> None:
        self._build_lookup_indexes()
        self._build_tier0_index()
        self._build_group_membership_index()
        self._build_edge_type_index()
        self._indexes_valid = True
        log.debug(
            "Graph indexes built: %d nodes, %d edges, %d tier-0",
            self.graph.number_of_nodes(), self.graph.number_of_edges(), len(self._tier0),
        )

    def _build_lookup_indexes(self) -> None:
        self._sam_index.clear()
        self._dn_index.clear()
        self._sid_index.clear()
        self._domain_index.clear()
        for nid, meta in self.entity_meta.items():
            sam = meta.get("sam_account_name")
            if sam:
                self._sam_index[sam.lower()] = nid
            dn = meta.get("distinguished_name")
            if dn:
                self._dn_index[dn.lower()] = nid
            sid = meta.get("object_sid")
            if sid:
                self._sid_index[sid] = nid
            domain = (meta.get("domain") or "").lower()
            if domain:
                self._domain_index.setdefault(domain, set()).add(nid)

    def _build_tier0_index(self) -> None:
        tier0: Set[str] = set()
        hvt: Set[str] = set()

        for nid, meta in self.entity_meta.items():
            etype = meta.get("type", "")
            is_cj = meta.get("is_crown_jewel", False)
            tier = meta.get("tier")
            sam = (meta.get("sam_account_name") or "").lower()

            if tier == 0 or is_cj:
                tier0.add(nid)
                hvt.add(nid)
                continue

            if etype in HVT_TYPES:
                tier0.add(nid)
                hvt.add(nid)
                continue

            for pattern in HVT_SAM_PATTERNS:
                if pattern in sam:
                    tier0.add(nid)
                    hvt.add(nid)
                    break
            else:
                if etype in ("CA", "CERT_TEMPLATE"):
                    hvt.add(nid)
                elif meta.get("is_admin_count") and etype in ("USER", "GROUP", "SERVICE_ACCOUNT"):
                    hvt.add(nid)
                elif tier == 1:
                    hvt.add(nid)

        self._tier0 = tier0
        self._hvt = hvt

        # Back-propagate tier=0 into entity_meta for consistency
        for nid in tier0:
            if self.entity_meta[nid].get("tier") is None:
                self.entity_meta[nid]["tier"] = 0

    def _build_group_membership_index(self) -> None:
        member_of: Dict[str, Set[str]] = defaultdict(set)
        group_members: Dict[str, Set[str]] = defaultdict(set)

        for src, tgt, data in self.graph.edges(data=True):
            if data.get("edge_type") == "MEMBER_OF":
                member_of[src].add(tgt)
                group_members[tgt].add(src)

        all_groups = {nid for nid, meta in self.entity_meta.items() if meta.get("type") == "GROUP"}

        # BFS from each group backwards to find all transitive members
        for grp in all_groups:
            visited: Set[str] = set()
            queue: deque = deque([grp])
            while queue:
                current = queue.popleft()
                for member in list(group_members.get(current, set())):
                    if member not in visited:
                        visited.add(member)
                        queue.append(member)
                        if self.entity_meta.get(member, {}).get("type") == "GROUP":
                            group_members[grp].add(member)
            group_members[grp] = visited

        for grp, members in group_members.items():
            for member in members:
                member_of[member].add(grp)

        self._group_members = dict(group_members)
        self._member_of = dict(member_of)

    def _build_edge_type_index(self) -> None:
        self._edge_type_index.clear()
        for u, v, key, data in self.graph.edges(data=True, keys=True):
            etype = data.get("edge_type", "")
            if etype:
                self._edge_type_index.setdefault(etype, []).append((u, v))

    def compute_communities(self) -> dict:
        """Compute Louvain community partition. Returns {node_id: community_int}."""
        import community as community_louvain  # python-louvain
        if self.graph.number_of_nodes() == 0:
            self.community_map = {}
            return {}
        undirected = self.graph.to_undirected(as_view=False)
        partition = community_louvain.best_partition(undirected, weight="risk_weight", random_state=42)
        self.community_map = partition
        for node_id, cid in partition.items():
            if node_id in self.entity_meta:
                self.entity_meta[node_id]["community_id"] = cid
        return partition

    def get_communities_summary(self) -> list:
        """Return list of {id, node_ids, size, label, risk_score} per community."""
        if not hasattr(self, 'community_map') or not self.community_map:
            self.compute_communities()
        communities: dict[int, list] = {}
        for node_id, cid in self.community_map.items():
            communities.setdefault(cid, []).append(node_id)
        result = []
        for cid, node_ids in communities.items():
            types = [self.entity_meta.get(n, {}).get("type", "") for n in node_ids]
            most_common_type = max(set(types), key=types.count) if types else "UNKNOWN"
            risks = [self.entity_meta.get(n, {}).get("risk_score", 0) for n in node_ids]
            result.append({
                "id": cid,
                "label": f"{most_common_type} cluster {cid}",
                "node_ids": node_ids,
                "size": len(node_ids),
                "risk_score": round(max(risks) if risks else 0, 2),
            })
        return sorted(result, key=lambda c: c["risk_score"], reverse=True)

    def compute_centrality_metrics(self) -> dict:
        """Compute betweenness, degree, eigenvector, pagerank. Returns {node_id: {metric: float}}."""
        if self.graph.number_of_nodes() == 0:
            return {}
        g = self.graph
        # Collapse MultiDiGraph to DiGraph (keeping max risk_weight per pair) for
        # algorithms that don't support multigraph types.
        dg = nx.DiGraph()
        for u, v, data in g.edges(data=True):
            if dg.has_edge(u, v):
                if data.get("risk_weight", 0.5) > dg[u][v].get("risk_weight", 0.5):
                    dg[u][v].update(data)
            else:
                dg.add_edge(u, v, **data)
        # Ensure all nodes are present (isolated nodes have no edges)
        for n in g.nodes():
            if n not in dg:
                dg.add_node(n)
        try:
            betweenness = nx.betweenness_centrality(dg, weight="risk_weight", normalized=True)
        except Exception:
            betweenness = {n: 0.0 for n in g.nodes()}
        degree = nx.degree_centrality(dg)
        try:
            pagerank = nx.pagerank(dg, weight="risk_weight", max_iter=100)
        except Exception:
            pagerank = {n: 0.0 for n in g.nodes()}
        try:
            eigenvector = nx.eigenvector_centrality(dg, weight="risk_weight", max_iter=500)
        except (nx.PowerIterationFailedConvergence, nx.NetworkXError):
            eigenvector = {n: 0.0 for n in g.nodes()}
        result = {}
        for node_id in g.nodes():
            result[node_id] = {
                "betweenness": round(betweenness.get(node_id, 0.0), 6),
                "degree_centrality": round(degree.get(node_id, 0.0), 6),
                "eigenvector": round(eigenvector.get(node_id, 0.0), 6),
                "pagerank": round(pagerank.get(node_id, 0.0), 6),
            }
        return result

    def get_neighborhood(self, node_id: str, hops: int = 2, max_nodes: int = 200) -> dict:
        """Return the subgraph within N hops of node_id (both directions)."""
        if node_id not in self.graph:
            return {"nodes": [], "edges": []}
        visited: set = {node_id}
        frontier = {node_id}
        for _ in range(hops):
            next_frontier: set = set()
            for n in frontier:
                next_frontier.update(self.graph.successors(n))
                next_frontier.update(self.graph.predecessors(n))
            new = next_frontier - visited
            visited.update(new)
            frontier = new
            if len(visited) >= max_nodes:
                break
        visited_list = list(visited)[:max_nodes]
        visited_set = set(visited_list)
        nodes = []
        for n in visited_list:
            meta = self.entity_meta.get(n, {})
            nodes.append({
                "id": n,
                "label": self._label_of(n),
                "entity_type": meta.get("type", "UNKNOWN"),
                "tier": meta.get("tier"),
                "is_crown_jewel": bool(meta.get("is_crown_jewel")),
                "is_admin_count": bool(meta.get("is_admin_count")),
                "community_id": meta.get("community_id"),
            })
        edges = []
        for u, v, key, data in self.graph.edges(data=True, keys=True):
            if u in visited_set and v in visited_set:
                edges.append({
                    "id": key,
                    "source": u,
                    "target": v,
                    "edge_type": data.get("edge_type", ""),
                    "risk_weight": data.get("risk_weight", 0.5),
                    "edge_confidence": data.get("edge_confidence", 1.0),
                    "edge_provenance_type": data.get("edge_provenance_type", "collected"),
                })
        return {"nodes": nodes, "edges": edges}

    def get_node(self, node_id: str) -> Optional[dict]:
        return self.entity_meta.get(str(node_id))

    def lookup_by_sam(self, sam: str) -> Optional[str]:
        return self._sam_index.get(sam.lower())

    def lookup_by_dn(self, dn: str) -> Optional[str]:
        return self._dn_index.get(dn.lower())

    def lookup_by_sid(self, sid: str) -> Optional[str]:
        return self._sid_index.get(sid)

    def get_tier0_nodes(self) -> Set[str]:
        return set(self._tier0)

    def get_high_value_targets(self) -> Set[str]:
        return set(self._hvt)

    def get_domain_nodes(self, domain: str) -> Set[str]:
        return set(self._domain_index.get(domain.lower(), set()))

    def get_transitive_group_members(self, group_id: str) -> Set[str]:
        return set(self._group_members.get(str(group_id), set()))

    def get_transitive_memberships(self, entity_id: str) -> Set[str]:
        return set(self._member_of.get(str(entity_id), set()))

    def is_tier0(self, node_id: str) -> bool:
        return node_id in self._tier0

    def _label_of(self, node_id: str) -> str:
        meta = self.entity_meta.get(node_id, {})
        return (
            meta.get("sam_account_name") or meta.get("display_name")
            or meta.get("dns_hostname") or node_id[:16]
        )

    def _type_of(self, node_id: str) -> str:
        return self.entity_meta.get(node_id, {}).get("type", "UNKNOWN")

    def _risk_weight_of_edge(self, src: str, tgt: str) -> float:
        edges = self.graph.get_edge_data(src, tgt)
        if not edges:
            return 0.5
        return max(d.get("risk_weight", 0.5) for d in edges.values())

    def get_reachable_from(self, source_id: str) -> Set[str]:
        try:
            return nx.descendants(self.graph, source_id)
        except nx.NodeNotFound:
            return set()

    def get_can_reach(self, target_id: str) -> Set[str]:
        try:
            return nx.ancestors(self.graph, target_id)
        except nx.NodeNotFound:
            return set()

    def get_neighbors(self, node_id: str, direction: str = "out") -> List[str]:
        if node_id not in self.graph:
            return []
        if direction == "out":
            return list(self.graph.successors(node_id))
        if direction == "in":
            return list(self.graph.predecessors(node_id))
        return list(set(self.graph.successors(node_id)) | set(self.graph.predecessors(node_id)))

    def find_shortest_path(
        self, source_id: str, target_id: str, max_hops: int = 12,
    ) -> Optional[AttackPath]:
        try:
            path = nx.shortest_path(self.graph, source_id, target_id)
            if len(path) - 1 > max_hops:
                return None
            return self._build_attack_path(path)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def find_all_shortest_paths(
        self, source_id: str, target_id: str, max_hops: int = 12, limit: int = 10,
    ) -> List[AttackPath]:
        results: List[AttackPath] = []
        try:
            for path in nx.all_shortest_paths(self.graph, source_id, target_id):
                if len(path) - 1 <= max_hops:
                    results.append(self._build_attack_path(path))
                if len(results) >= limit:
                    break
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass
        return results

    def get_all_paths(
        self, source_id: str, target_id: str, max_hops: int = 8, max_paths: int = 10,
    ) -> List[PathResult]:
        seen_paths: Set[Tuple[str, ...]] = set()
        results: List[PathResult] = []

        try:
            for path in nx.all_shortest_paths(self.graph, source_id, target_id):
                key = tuple(path)
                if key not in seen_paths and len(path) - 1 <= max_hops:
                    seen_paths.add(key)
                    results.append(self._build_path_result(path))
                if len(results) >= max_paths:
                    return results
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return results

        iters = 0
        try:
            for path in nx.all_simple_paths(self.graph, source_id, target_id, cutoff=max_hops):
                iters += 1
                if iters > _MAX_SIMPLE_PATH_ITERS:
                    break
                key = tuple(path)
                if key not in seen_paths:
                    seen_paths.add(key)
                    results.append(self._build_path_result(path))
                if len(results) >= max_paths:
                    break
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

        results.sort(key=lambda r: (r.hop_count, -r.path_score))
        return results

    def find_k_shortest_paths(
        self, source_id: str, target_id: str, k: int = 5, max_hops: int = 12,
    ) -> List[AttackPath]:
        if source_id not in self.graph or target_id not in self.graph:
            return []

        # shortest_simple_paths is not implemented for MultiDiGraph;
        # collapse to DiGraph keeping highest-risk edge between each pair.
        dg = nx.DiGraph()
        for u, v, data in self.graph.edges(data=True):
            if dg.has_edge(u, v):
                if data.get("risk_weight", 0.5) > dg[u][v].get("risk_weight", 0.5):
                    dg[u][v].update(data)
            else:
                dg.add_edge(u, v, **data)

        results: List[AttackPath] = []
        try:
            for path in nx.shortest_simple_paths(
                dg, source_id, target_id,
                weight=lambda u, v, d: 1.0 - d.get("risk_weight", 0.5),
            ):
                if len(path) - 1 > max_hops:
                    continue
                results.append(self._build_attack_path(path))
                if len(results) >= k:
                    break
        except (nx.NetworkXNoPath, nx.NodeNotFound, nx.NetworkXError):
            pass

        results.sort(key=lambda p: p.path_score, reverse=True)
        return results

    def find_directed_path(self, source_id: str, target_id: str) -> Optional["AttackPath"]:
        """Find shortest directed path using Dijkstra (respects edge direction)."""
        if source_id not in self.graph or target_id not in self.graph:
            return None
        try:
            path = nx.dijkstra_path(
                self.graph, source_id, target_id,
                weight=lambda u, v, d: 1.0 - max(
                    (data.get("risk_weight", 0.5) for data in d.values()), default=0.5
                ),
            )
            return self._build_attack_path(path)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def get_paths_to_tier0(
        self, source_id: str, max_hops: int = 10, max_paths: int = 10,
    ) -> List[PathResult]:
        results: List[PathResult] = []
        seen: Set[Tuple[str, ...]] = set()

        for t0 in self._tier0:
            if t0 == source_id:
                continue
            try:
                for path in nx.all_shortest_paths(self.graph, source_id, t0):
                    if len(path) - 1 > max_hops:
                        continue
                    key = tuple(path)
                    if key not in seen:
                        seen.add(key)
                        results.append(self._build_path_result(path))
                    if len(results) >= max_paths * 3:  # collect more, then trim
                        break
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        results.sort(key=lambda r: r.path_score, reverse=True)
        return results[:max_paths]

    def find_attack_paths_to_tier0(
        self, source_id: str, max_hops: int = 10, max_paths: int = 10,
    ) -> List[AttackPath]:
        pr_list = self.get_paths_to_tier0(source_id, max_hops, max_paths)
        return [self._pathresult_to_attackpath(pr) for pr in pr_list]

    def find_paths_from_owned(
        self,
        targets: Optional[Set[str]] = None,
        max_hops: int = 10,
        max_paths_per_source: int = 3,
    ) -> List[AttackPath]:
        if not self._owned:
            return []
        dest = targets if targets is not None else self._tier0
        results: List[AttackPath] = []

        for owned in self._owned:
            if owned not in self.graph:
                continue
            count = 0
            for t0 in dest:
                if t0 == owned:
                    continue
                ap = self.find_shortest_path(owned, t0, max_hops=max_hops)
                if ap:
                    results.append(ap)
                    count += 1
                    if count >= max_paths_per_source:
                        break

        results.sort(key=lambda p: p.path_score, reverse=True)
        return results

    def find_paths_to_domain_admins(
        self,
        source_id: Optional[str] = None,
        max_hops: int = 10,
        max_paths: int = 10,
    ) -> List[AttackPath]:
        da_nodes = {
            nid for nid, meta in self.entity_meta.items()
            if "domain admins" in (meta.get("sam_account_name") or "").lower()
        }
        if not da_nodes:
            da_nodes = self._tier0

        sources = [source_id] if source_id else list(self._owned)
        results: List[AttackPath] = []

        for src in sources:
            for da in da_nodes:
                ap = self.find_shortest_path(src, da, max_hops=max_hops)
                if ap:
                    results.append(ap)
            if len(results) >= max_paths:
                break

        results.sort(key=lambda p: p.path_score, reverse=True)
        return results[:max_paths]

    def compute_tier0_blast_radius(self) -> Dict[str, int]:
        if not self._tier0:
            return {}

        reach_count: Dict[str, int] = {}
        rev = self.graph.reverse(copy=False)

        for t0 in self._tier0:
            if t0 not in rev:
                continue
            for ancestor in nx.descendants(rev, t0):
                if ancestor not in self._tier0:
                    reach_count[ancestor] = reach_count.get(ancestor, 0) + 1

        return reach_count

    def compute_blast_radius_detail(self) -> GraphBlastRadiusResult:
        raw = self.compute_tier0_blast_radius()
        total = len([nid for nid in self.entity_meta if nid not in self._tier0])
        reachable = len(raw)
        reach_pct = round(reachable / max(total, 1) * 100, 1)

        top = sorted(raw.items(), key=lambda x: x[1], reverse=True)[:50]
        top_exposed = [
            {
                "id": nid, "label": self._label_of(nid), "type": self._type_of(nid),
                "tier0_reach_count": cnt,
                "risk": min(100, round(cnt / max(len(self._tier0), 1) * 100, 1)),
            }
            for nid, cnt in top
        ]

        return GraphBlastRadiusResult(
            total_non_tier0_nodes=total, reachable_count=reachable,
            reach_pct=reach_pct, tier0_reached=len(self._tier0), top_exposed=top_exposed,
        )

    def compute_node_blast_radius(self, node_id: str) -> Dict[str, Any]:
        reachable = self.get_reachable_from(node_id)
        tier0_reachable = reachable & self._tier0
        hvt_reachable = reachable & self._hvt

        return {
            "node_id": node_id, "label": self._label_of(node_id),
            "reachable_count": len(reachable),
            "tier0_reachable": len(tier0_reachable),
            "hvt_reachable": len(hvt_reachable),
            "tier0_ids": list(tier0_reachable),
            "can_dominate": len(tier0_reachable) > 0,
            "dominance_pct": round(len(tier0_reachable) / max(len(self._tier0), 1) * 100, 1),
        }

    def compute_domain_dominance(
        self, owned_node_ids: Optional[Iterable[str]] = None,
    ) -> DomainDominanceResult:
        sources = set(owned_node_ids or self._owned)
        reachable_tier0: Set[str] = set()

        for src in sources:
            reachable = self.get_reachable_from(src)
            reachable_tier0 |= (reachable & self._tier0)

        dominance_pct = round(len(reachable_tier0) / max(len(self._tier0), 1) * 100, 1)

        # Find critical path: owned → tier0 with highest score
        best_path: Optional[AttackPath] = None
        for src in sources:
            for t0 in reachable_tier0:
                ap = self.find_shortest_path(src, t0)
                if ap and (best_path is None or ap.path_score > best_path.path_score):
                    best_path = ap

        domains: Dict[str, int] = defaultdict(int)
        for nid in self._tier0:
            domain = (self.entity_meta.get(nid, {}).get("domain") or "").lower()
            if domain:
                domains[domain] += 1
        primary_domain = max(domains, key=lambda d: domains[d]) if domains else "unknown"

        return DomainDominanceResult(
            domain=primary_domain, tier0_total=len(self._tier0),
            tier0_reachable_from_source=len(reachable_tier0),
            dominance_pct=dominance_pct, owned_paths=len(sources), critical_path=best_path,
        )

    def compute_exposure_surface(self) -> Dict[str, Any]:
        surface: Set[str] = set()
        rev = self.graph.reverse(copy=False)
        for t0 in self._tier0:
            if t0 in rev:
                surface |= nx.descendants(rev, t0)
        surface -= self._tier0

        user_surface = sum(
            1 for nid in surface if self._type_of(nid) in ("USER", "SERVICE_ACCOUNT", "GMSA")
        )
        computer_surface = sum(
            1 for nid in surface if self._type_of(nid) in ("COMPUTER", "DC")
        )

        return {
            "total_surface": len(surface),
            "user_count": user_surface,
            "computer_count": computer_surface,
            "surface_pct": round(len(surface) / max(self.graph.number_of_nodes(), 1) * 100, 1),
            "node_ids": list(surface),
        }

    def detect_shadow_admins(self) -> List[ShadowAdmin]:
        results: List[ShadowAdmin] = []
        control_etypes = CONTROL_EDGES - {"MEMBER_OF", "CONTAINS"}

        for nid, meta in self.entity_meta.items():
            if nid in self._tier0:
                continue
            if meta.get("is_admin_count"):
                continue
            if not meta.get("is_enabled", True):
                continue

            control_targets: List[str] = []
            control_paths: List[str] = []

            for succ in self.graph.successors(nid):
                if succ in self._tier0:
                    etype = self.graph[nid][succ].get("edge_type", "")
                    if etype in control_etypes:
                        control_targets.append(succ)
                        control_paths.append(etype)

            if control_targets:
                risk = min(100.0, len(control_targets) * 25.0 +
                           sum(EDGE_RISK.get(e, 0.5) for e in control_paths) * 20.0)
                results.append(ShadowAdmin(
                    entity_id=nid, entity_label=self._label_of(nid),
                    entity_type=self._type_of(nid), control_paths=control_paths,
                    targets=control_targets, risk_score=round(risk, 1),
                ))

        results.sort(key=lambda s: s.risk_score, reverse=True)
        return results

    def detect_acl_abuse_paths(self, max_paths: int = 50) -> List[AttackPath]:
        acl_edge_types = {"WRITE_DACL", "WRITE_OWNER", "GENERIC_ALL", "OWNS",
                          "FORCE_CHANGE_PASSWORD", "ADD_MEMBER"}
        results: List[AttackPath] = []
        seen: Set[Tuple[str, ...]] = set()

        for src, tgt, data in self.graph.edges(data=True):
            etype = data.get("edge_type", "")
            if etype not in acl_edge_types:
                continue
            if src in self._tier0:
                continue

            if tgt in self._tier0:
                path = [src, tgt]
                key = tuple(path)
                if key not in seen:
                    seen.add(key)
                    results.append(self._build_attack_path(path))
                continue

            if etype == "ADD_MEMBER":
                groups_of_tgt = self.get_transitive_memberships(tgt)
                if groups_of_tgt & self._tier0:
                    path = [src, tgt]
                    key = tuple(path)
                    if key not in seen:
                        seen.add(key)
                        results.append(self._build_attack_path(path))

        results.sort(key=lambda p: p.path_score, reverse=True)
        return results[:max_paths]

    def detect_dcsync_principals(self) -> List[Dict[str, Any]]:
        principals: List[Dict[str, Any]] = []
        for src, tgt, data in self.graph.edges(data=True):
            if data.get("edge_type") == "DCSYNC":
                classification = classify_dcsync_principal(self.entity_meta.get(src, {}))
                principals.append({
                    "principal_id": src, "principal_label": self._label_of(src),
                    "principal_type": self._type_of(src), "target_id": tgt,
                    "target_label": self._label_of(tgt),
                    "classification": classification,
                    "is_expected": classification == "expected",
                    "risk_score": 100.0,
                })
        principals.sort(key=lambda p: (p["is_expected"], p["principal_label"].lower()))
        return principals

    def detect_unconstrained_delegation(self) -> List[DelegationChain]:
        results: List[DelegationChain] = []
        for nid, meta in self.entity_meta.items():
            if not meta.get("uac_trusted_for_deleg"):
                continue
            if self._type_of(nid) not in ("COMPUTER", "SERVICE_ACCOUNT", "DC"):
                continue

            reachable = self.get_reachable_from(nid)
            tier0_reach = list(reachable & self._tier0)
            risk = 90.0 + (10.0 if tier0_reach else 0.0)

            results.append(DelegationChain(
                entity_id=nid, entity_label=self._label_of(nid),
                entity_type=self._type_of(nid), delegation_type="unconstrained",
                delegation_targets=["* (any service via TGT theft)"],
                can_reach_tier0=bool(tier0_reach), tier0_targets=tier0_reach[:10],
                risk_score=round(risk, 1),
            ))

        results.sort(key=lambda d: d.risk_score, reverse=True)
        return results

    def detect_constrained_delegation_abuse(self) -> List[DelegationChain]:
        results: List[DelegationChain] = []
        for src, tgt, data in self.graph.edges(data=True):
            if data.get("edge_type") != "ALLOWED_TO_DELEGATE":
                continue
            if self.entity_meta.get(src, {}).get("uac_trusted_to_auth_deleg"):
                dtype = "s4u2self+proxy"  # protocol transition → any user
                risk_base = 85.0
            else:
                dtype = "constrained"
                risk_base = 70.0

            reachable = self.get_reachable_from(tgt)
            tier0_via_target = list((reachable | {tgt}) & self._tier0)
            risk = risk_base + (15.0 if tier0_via_target else 0.0)

            results.append(DelegationChain(
                entity_id=src, entity_label=self._label_of(src),
                entity_type=self._type_of(src), delegation_type=dtype,
                delegation_targets=[self._label_of(tgt)],
                can_reach_tier0=bool(tier0_via_target), tier0_targets=tier0_via_target[:10],
                risk_score=round(risk, 1),
            ))

        results.sort(key=lambda d: d.risk_score, reverse=True)
        return results

    def detect_rbcd_abuse(self) -> List[DelegationChain]:
        results: List[DelegationChain] = []
        for src, tgt, data in self.graph.edges(data=True):
            if data.get("edge_type") != "ALLOWED_TO_ACT":
                continue
            tier0_tgt = [tgt] if tgt in self._tier0 else []
            reachable_via_tgt = self.get_reachable_from(tgt) & self._tier0
            all_t0 = list(set(tier0_tgt) | reachable_via_tgt)
            risk = 80.0 + (20.0 if all_t0 else 0.0)
            results.append(DelegationChain(
                entity_id=src, entity_label=self._label_of(src),
                entity_type=self._type_of(src), delegation_type="rbcd",
                delegation_targets=[self._label_of(tgt)],
                can_reach_tier0=bool(all_t0), tier0_targets=all_t0[:10],
                risk_score=round(risk, 1),
            ))
        results.sort(key=lambda d: d.risk_score, reverse=True)
        return results

    def detect_kerberoastable_paths(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for nid, meta in self.entity_meta.items():
            if not meta.get("has_spn"):
                continue
            if not meta.get("is_enabled", True):
                continue
            if self._type_of(nid) not in ("USER", "SERVICE_ACCOUNT"):
                continue

            reachable = self.get_reachable_from(nid)
            tier0_reach = list(reachable & self._tier0)
            if not tier0_reach:
                continue

            best_hops: Optional[int] = None
            for t0 in tier0_reach[:5]:
                try:
                    length = nx.shortest_path_length(self.graph, nid, t0)
                    if best_hops is None or length < best_hops:
                        best_hops = length
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    pass

            results.append({
                "account_id": nid, "account_label": self._label_of(nid),
                "account_type": self._type_of(nid), "tier0_reachable": len(tier0_reach),
                "min_hops_to_tier0": best_hops,
                "risk_score": round(min(100, 60 + (10 if (best_hops or 99) <= 2 else 0)
                                        + len(tier0_reach) * 2), 1),
                "attack": "Kerberoast SPN → crack service ticket → account compromise",
            })

        results.sort(key=lambda r: r["risk_score"], reverse=True)
        return results

    def detect_asrep_roastable(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for nid, meta in self.entity_meta.items():
            if not meta.get("uac_dont_req_preauth"):
                continue
            if not meta.get("is_enabled", True):
                continue

            reachable = self.get_reachable_from(nid)
            tier0_reach = list(reachable & self._tier0)

            results.append({
                "account_id": nid, "account_label": self._label_of(nid),
                "account_type": self._type_of(nid), "tier0_reachable": len(tier0_reach),
                "risk_score": round(min(100, 70 + len(tier0_reach) * 3), 1),
                "attack": "AS-REP roast → offline crack → account compromise",
            })

        results.sort(key=lambda r: r["risk_score"], reverse=True)
        return results

    def detect_password_not_required(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for nid, meta in self.entity_meta.items():
            if not meta.get("uac_passwd_notreqd"):
                continue
            if not meta.get("is_enabled", True):
                continue
            reachable = self.get_reachable_from(nid)
            t0_reach = len(reachable & self._tier0)
            results.append({
                "account_id": nid, "account_label": self._label_of(nid),
                "account_type": self._type_of(nid), "tier0_reachable": t0_reach,
                "risk_score": round(min(100, 50 + t0_reach * 5), 1),
                "attack": "Empty password attempt → account access",
            })
        results.sort(key=lambda r: r["risk_score"], reverse=True)
        return results

    def detect_adcs_paths(self) -> List[ADCSPath]:
        paths: List[ADCSPath] = []

        for template in self._cert_templates:
            name = template.get("name", "Unknown")
            ca = template.get("ca_name", "Unknown")
            esc1 = template.get("esc1_vulnerable", False)
            esc2 = template.get("esc2_vulnerable", False)
            esc3 = template.get("esc3_vulnerable", False)
            esc4 = template.get("esc4_vulnerable", False)
            enrollee_supplies = template.get("enrollee_supplies_subject", False)
            auth_sigs = template.get("authorized_signatures_required", 0)
            manager_approval = template.get("requires_manager_approval", False)
            ekus = template.get("ekus", []) or []

            enrolling: List[str] = []
            for src, tgt, data in self.graph.edges(data=True):
                if (data.get("edge_type") == "CAN_ENROLL"
                        and (self._label_of(tgt) == name
                             or self._type_of(tgt) == "CERT_TEMPLATE")):
                    enrolling.append(self._label_of(src))

            if esc1 or (enrollee_supplies and not manager_approval and auth_sigs == 0
                        and any("client authentication" in str(e).lower() for e in ekus)):
                paths.append(ADCSPath(
                    template_name=name, ca_name=ca, esc_type="ESC1",
                    enrolling_principals=enrolling, risk_score=95.0,
                    description=(
                        f"ESC1: Template '{name}' allows enrollees to supply an arbitrary "
                        "Subject Alternative Name (SAN). Attacker can enroll as any domain "
                        "user including Domain Admins."
                    ),
                ))

            if esc2 or (enrollee_supplies and not manager_approval and auth_sigs == 0):
                if not any(p.esc_type == "ESC1" and p.template_name == name for p in paths):
                    paths.append(ADCSPath(
                        template_name=name, ca_name=ca, esc_type="ESC2",
                        enrolling_principals=enrolling, risk_score=88.0,
                        description=(
                            f"ESC2: Template '{name}' has the Any Purpose EKU or no EKU. "
                            "Can be used to enroll certificates for any purpose."
                        ),
                    ))

            if esc3:
                paths.append(ADCSPath(
                    template_name=name, ca_name=ca, esc_type="ESC3",
                    enrolling_principals=enrolling, risk_score=82.0,
                    description=(
                        f"ESC3: Template '{name}' is a Certificate Request Agent template. "
                        "Attacker can enroll on behalf of other users."
                    ),
                ))

            if esc4:
                paths.append(ADCSPath(
                    template_name=name, ca_name=ca, esc_type="ESC4",
                    enrolling_principals=enrolling, risk_score=85.0,
                    description=(
                        f"ESC4: Template '{name}' has vulnerable ACLs — a low-privileged "
                        "principal can write to the template and re-configure it for ESC1."
                    ),
                ))

        for nid, meta in self.entity_meta.items():
            if self._type_of(nid) != "CA":
                continue
            attrs = meta.get("attributes", {}) or {}
            if attrs.get("esc6_vulnerable") or attrs.get("editf_altsubjectname"):
                paths.append(ADCSPath(
                    template_name="*", ca_name=self._label_of(nid), esc_type="ESC6",
                    enrolling_principals=["Any authenticated user"], risk_score=90.0,
                    description=(
                        f"ESC6: CA '{self._label_of(nid)}' has EDITF_ATTRIBUTESUBJECTALTNAME2 "
                        "enabled. Any enrollment can include arbitrary SANs."
                    ),
                ))

        for nid, meta in self.entity_meta.items():
            if self._type_of(nid) != "CA":
                continue
            attrs = meta.get("attributes", {}) or {}
            if attrs.get("esc8_vulnerable") or attrs.get("http_enrollment_enabled"):
                paths.append(ADCSPath(
                    template_name="*", ca_name=self._label_of(nid), esc_type="ESC8",
                    enrolling_principals=["Any NTLM-authenticated user (relay)"], risk_score=92.0,
                    description=(
                        f"ESC8: CA '{self._label_of(nid)}' exposes HTTP enrollment. "
                        "Attacker can NTLM-relay any computer account to obtain a certificate."
                    ),
                ))

        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def compute_betweenness_centrality(
        self, attack_subgraph_only: bool = True, top_n: int = 25, sample_k: int = 500,
    ) -> List[Dict[str, Any]]:
        g = self._get_attack_subgraph() if attack_subgraph_only else self.graph
        if g.number_of_nodes() == 0:
            return []

        # Use approximate centrality for large graphs
        if g.number_of_nodes() > sample_k:
            bc = nx.betweenness_centrality(g, k=min(sample_k, g.number_of_nodes()),
                                            normalized=True, weight=None)
        else:
            bc = nx.betweenness_centrality(g, normalized=True, weight=None)

        top = sorted(bc.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [
            {
                "node_id": nid, "label": self._label_of(nid), "type": self._type_of(nid),
                "tier": self.entity_meta.get(nid, {}).get("tier"),
                "is_tier0": nid in self._tier0, "betweenness_score": round(score, 6), "rank": i + 1,
            }
            for i, (nid, score) in enumerate(top)
        ]

    def compute_pagerank(
        self, top_n: int = 25, attack_subgraph_only: bool = True,
    ) -> List[Dict[str, Any]]:
        g = self._get_attack_subgraph() if attack_subgraph_only else self.graph
        if g.number_of_nodes() == 0:
            return []

        pr = nx.pagerank(g, alpha=0.85, max_iter=200, weight="risk_weight")
        top = sorted(pr.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [
            {
                "node_id": nid, "label": self._label_of(nid), "type": self._type_of(nid),
                "tier": self.entity_meta.get(nid, {}).get("tier"),
                "is_tier0": nid in self._tier0, "pagerank_score": round(score, 8), "rank": i + 1,
            }
            for i, (nid, score) in enumerate(top)
        ]

    def find_choke_points(self, top_n: int = 20) -> List[ChokePoint]:
        attack_g = self._get_attack_subgraph()
        if attack_g.number_of_nodes() < 3:
            return []

        undirected = attack_g.to_undirected()
        try:
            art_points = set(nx.articulation_points(undirected))
        except Exception:
            import logging
            logging.getLogger(__name__).warning("Articulation points calculation failed", exc_info=True)
            art_points = set()

        n = min(attack_g.number_of_nodes(), 200)
        try:
            bc = nx.betweenness_centrality(attack_g, k=n, normalized=True)
        except Exception:
            import logging
            logging.getLogger(__name__).warning("Betweenness centrality calculation failed", exc_info=True)
            bc = {}

        before = self._count_paths_to_tier0()
        choke_nodes = list(
            (art_points | set(sorted(bc, key=lambda x: bc.get(x, 0), reverse=True)[:top_n * 2]))
            - self._tier0
        )[:top_n * 3]

        results: List[ChokePoint] = []
        for nid in choke_nodes:
            if nid not in self.graph:
                continue
            g_copy = self.graph.copy()
            g_copy.remove_node(nid)
            after = self._count_paths_to_tier0(graph=g_copy)
            impact = round((before - after) / max(before, 1), 4)

            results.append(ChokePoint(
                node_id=nid, node_label=self._label_of(nid), node_type=self._type_of(nid),
                attack_paths_through=before - after, is_articulation_point=nid in art_points,
                betweenness_score=round(bc.get(nid, 0.0), 6), remediation_impact=impact,
            ))

        results.sort(key=lambda c: (c.remediation_impact, c.betweenness_score), reverse=True)
        return results[:top_n]

    def find_most_traversed_edges(self, top_n: int = 20) -> List[Dict[str, Any]]:
        attack_g = self._get_attack_subgraph()
        if attack_g.number_of_edges() == 0:
            return []

        # edge_betweenness_centrality is not implemented for MultiDiGraph;
        # collapse to DiGraph keeping highest-risk edge between each pair.
        dg = nx.DiGraph()
        for u, v, data in attack_g.edges(data=True):
            if dg.has_edge(u, v):
                if data.get("risk_weight", 0.5) > dg[u][v].get("risk_weight", 0.5):
                    dg[u][v].update(data)
            else:
                dg.add_edge(u, v, **data)

        try:
            ebc = nx.edge_betweenness_centrality(dg, normalized=True)
        except Exception:
            return []

        top = sorted(ebc.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [
            {
                "source_id": src, "target_id": tgt,
                "source_label": self._label_of(src), "target_label": self._label_of(tgt),
                "edge_type": dg.get_edge_data(src, tgt, {}).get("edge_type", ""),
                "betweenness_score": round(score, 6), "rank": i + 1,
            }
            for i, ((src, tgt), score) in enumerate(top)
        ]

    def find_critical_nodes(self, top_n: int = 15) -> List[Dict[str, Any]]:
        blast_before = len(self.compute_tier0_blast_radius())
        candidates = self.compute_betweenness_centrality(top_n=top_n * 2)

        results: List[Dict[str, Any]] = []
        for cand in candidates[:top_n]:
            nid = cand["node_id"]
            if nid in self._tier0:
                continue
            g_copy = self.graph.copy()
            g_copy.remove_node(nid)

            tmp = ADGraphAnalyzer()
            tmp.graph = g_copy
            tmp.entity_meta = {k: v for k, v in self.entity_meta.items() if k != nid}
            tmp._tier0 = self._tier0 - {nid}
            blast_after = len(tmp.compute_tier0_blast_radius())

            reduction = blast_before - blast_after
            results.append({
                "node_id": nid, "label": self._label_of(nid), "type": self._type_of(nid),
                "tier": self.entity_meta.get(nid, {}).get("tier"),
                "blast_radius_reduction": reduction,
                "reduction_pct": round(reduction / max(blast_before, 1) * 100, 1),
                "betweenness_score": cand["betweenness_score"],
            })

        results.sort(key=lambda r: r["blast_radius_reduction"], reverse=True)
        return results[:top_n]

    def simulate_edge_removal(self, edge_removals: List[Tuple[str, str]]) -> Dict[str, Any]:
        before = self._count_paths_to_tier0()
        blast_before = len(self.compute_tier0_blast_radius())

        # ── Phase 1: Per-edge individual impact analysis ─────────────────────
        per_edge_analysis: List[Dict[str, Any]] = []
        for src, tgt in edge_removals:
            if not self.graph.has_edge(src, tgt):
                continue
            # MultiDiGraph: get_edge_data returns {key: data_dict}
            _edge_data_map = self.graph.get_edge_data(src, tgt) or {}
            edge_data = max(_edge_data_map.values(), key=lambda d: d.get("risk_weight", 0.5)) if _edge_data_map else {}
            etype = edge_data.get("edge_type", "UNKNOWN")
            rw = _safe_float(edge_data.get("risk_weight"), EDGE_RISK.get(etype, 0.5))
            g_test = self.graph.copy()
            g_test.remove_edge(src, tgt)
            after_test = self._count_paths_to_tier0(graph=g_test)
            elim = before - after_test
            per_edge_analysis.append({
                "source": src,
                "target": tgt,
                "source_label": self._label_of(src),
                "target_label": self._label_of(tgt),
                "edge_type": etype,
                "risk_weight": round(rw, 3),
                "exposed_principals_eliminated_if_removed": elim,
                "reduction_pct_if_removed": round(elim / max(before, 1) * 100, 1),
                "remediation": _remediation_for_edge(etype, self._label_of(src), self._label_of(tgt)),
                "remediation_steps": _remediation_steps_for_edge(etype, self._label_of(src), self._label_of(tgt)),
            })
        per_edge_analysis.sort(key=lambda x: x["exposed_principals_eliminated_if_removed"], reverse=True)
        optimal: Dict[str, Any] | None = per_edge_analysis[0] if per_edge_analysis else None

        # ── Phase 2: Remove all requested edges ──────────────────────────────
        g_copy = self.graph.copy()
        actually_removed: List[Dict[str, Any]] = []
        for src, tgt in edge_removals:
            if g_copy.has_edge(src, tgt):
                _em = g_copy.get_edge_data(src, tgt) or {}
                _ed = max(_em.values(), key=lambda d: d.get("risk_weight", 0.5)) if _em else {}
                etype = _ed.get("edge_type", "")
                g_copy.remove_edge(src, tgt)
                actually_removed.append({
                    "source": src, "target": tgt,
                    "source_label": self._label_of(src), "target_label": self._label_of(tgt),
                    "edge_type": etype,
                    "remediation": _remediation_for_edge(etype, self._label_of(src), self._label_of(tgt)),
                    "remediation_steps": _remediation_steps_for_edge(etype, self._label_of(src), self._label_of(tgt)),
                })

        after = self._count_paths_to_tier0(graph=g_copy)
        tmp = ADGraphAnalyzer()
        tmp.graph = g_copy
        tmp.entity_meta = self.entity_meta
        tmp._tier0 = self._tier0
        blast_after = len(tmp.compute_tier0_blast_radius())

        # ── Phase 3: Discover alternative paths still reachable ──────────────
        alternative_paths: List[Dict[str, Any]] = []
        if after > 0:
            sources_to_check = sorted({src for src, _ in edge_removals if src not in self._tier0})[:4]
            seen_alt: Set[Tuple[str, str]] = set()
            for src_id in sources_to_check:
                if not g_copy.has_node(src_id):
                    continue
                for t0 in sorted(self._tier0)[:6]:
                    if not g_copy.has_node(t0):
                        continue
                    try:
                        alt = nx.shortest_path(g_copy, src_id, t0)
                        key = (src_id, t0)
                        if key in seen_alt or len(alt) < 2:
                            continue
                        seen_alt.add(key)
                        alt_etypes = []
                        for i in range(len(alt) - 1):
                            _aem = g_copy.get_edge_data(alt[i], alt[i + 1]) or {}
                            _aed = max(_aem.values(), key=lambda d: d.get("risk_weight", 0.5)) if _aem else {}
                            alt_etypes.append(_aed.get("edge_type", "EDGE"))
                        alternative_paths.append({
                            "source_label": self._label_of(src_id),
                            "target_label": self._label_of(t0),
                            "hop_count": len(alt) - 1,
                            "edge_types": alt_etypes,
                        })
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        pass
        alternative_paths = alternative_paths[:4]

        # ── Phase 4: Residual risk score ─────────────────────────────────────
        if blast_before > 0:
            residual_risk_score = round(blast_after / blast_before * 100, 1)
        else:
            residual_risk_score = 0.0

        return {
            "before": before,
            "after": after,
            "eliminated": before - after,
            "reduction_pct": round((before - after) / max(before, 1) * 100, 1),
            "metric": "exposed_principals_reaching_tier0",
            "exposed_principals_before": before,
            "exposed_principals_after": after,
            "exposed_principals_eliminated": before - after,
            "blast_radius_before": blast_before,
            "blast_radius_after": blast_after,
            "blast_radius_reduction": blast_before - blast_after,
            "edges_removed": actually_removed,
            "edges_requested": len(edge_removals),
            "per_edge_analysis": per_edge_analysis,
            "optimal_removal": optimal,
            "alternative_paths": alternative_paths,
            "residual_risk_score": residual_risk_score,
            "is_fully_remediated": after == 0,
        }

    def simulate_node_hardening(self, node_ids: List[str]) -> Dict[str, Any]:
        before = self._count_paths_to_tier0()
        blast_before = len(self.compute_tier0_blast_radius())

        g_copy = self.graph.copy()
        for nid in node_ids:
            if g_copy.has_node(nid) and nid not in self._tier0:
                g_copy.remove_node(nid)

        after = self._count_paths_to_tier0(graph=g_copy)

        tmp = ADGraphAnalyzer()
        tmp.graph = g_copy
        tmp.entity_meta = {k: v for k, v in self.entity_meta.items() if k not in node_ids}
        tmp._tier0 = self._tier0 - set(node_ids)
        blast_after = len(tmp.compute_tier0_blast_radius())

        return {
            "nodes_hardened": [self._label_of(nid) for nid in node_ids],
            "paths_before": before, "paths_after": after,
            "paths_eliminated": before - after,
            "reduction_pct": round((before - after) / max(before, 1) * 100, 1),
            "blast_radius_before": blast_before, "blast_radius_after": blast_after,
            "blast_radius_reduction": blast_before - blast_after,
        }

    def rank_remediation_actions(self, max_results: int = 30) -> List[Dict[str, Any]]:
        before = self._count_paths_to_tier0()
        if before == 0:
            return []

        attack_g = self._get_attack_subgraph()
        # edge_betweenness_centrality not implemented for MultiDiGraph;
        # collapse to DiGraph for betweenness computation.
        _dg = nx.DiGraph()
        for u, v, _d in attack_g.edges(data=True):
            if _dg.has_edge(u, v):
                if _d.get("risk_weight", 0.5) > _dg[u][v].get("risk_weight", 0.5):
                    _dg[u][v].update(_d)
            else:
                _dg.add_edge(u, v, **_d)
        ebc = {}
        try:
            ebc = nx.edge_betweenness_centrality(_dg, normalized=True)
        except Exception:
            pass

        # Top edges by betweenness as candidates (avoid O(E) simulation)
        top_edges = sorted(
            [(src, tgt) for src, tgt in attack_g.edges()
             if not (src in self._tier0 and tgt in self._tier0)],
            key=lambda e: ebc.get(e, 0), reverse=True,
        )[:max_results * 3]

        results: List[Dict[str, Any]] = []
        for src, tgt in top_edges:
            _em = self.graph.get_edge_data(src, tgt) or {}
            data = max(_em.values(), key=lambda d: d.get("risk_weight", 0.5)) if _em else {}
            etype = data.get("edge_type", "")
            rw = data.get("risk_weight", 0.5)
            g_copy = self.graph.copy()
            g_copy.remove_edge(src, tgt)
            after = self._count_paths_to_tier0(graph=g_copy)
            eliminated = before - after
            if eliminated == 0:
                continue
            results.append({
                "source_id": src, "target_id": tgt,
                "source_label": self._label_of(src), "target_label": self._label_of(tgt),
                "edge_type": etype, "risk_weight": rw,
                "paths_eliminated": eliminated,
                "reduction_pct": round(eliminated / max(before, 1) * 100, 1),
                "betweenness": round(ebc.get((src, tgt), 0), 6),
                "remediation": _remediation_for_edge(etype, self._label_of(src), self._label_of(tgt)),
            })

        results.sort(key=lambda r: r["paths_eliminated"], reverse=True)
        return results[:max_results]

    def get_cross_domain_paths(self, max_paths: int = 20) -> List[Dict[str, Any]]:
        trust_edges = self._edge_type_index.get("TRUSTS", [])
        if not trust_edges:
            return []

        results: List[Dict[str, Any]] = []
        for src, tgt in trust_edges:
            src_domain = (self.entity_meta.get(src, {}).get("domain") or "").lower()
            tgt_domain = (self.entity_meta.get(tgt, {}).get("domain") or "").lower()

            reachable_from_tgt = self.get_reachable_from(tgt)
            tier0_via_trust = reachable_from_tgt & self._tier0
            if not tier0_via_trust:
                continue

            for t0 in list(tier0_via_trust)[:3]:
                ap = self.find_shortest_path(src, t0)
                if ap:
                    results.append({
                        "trust_source": src, "trust_target": tgt,
                        "source_domain": src_domain, "target_domain": tgt_domain,
                        "trust_label": f"{src_domain} → {tgt_domain}",
                        "tier0_target": t0, "tier0_label": self._label_of(t0),
                        "path_score": ap.path_score, "hop_count": ap.hop_count,
                        "risk": "Cross-domain Tier-0 reachable via trust traversal",
                    })

        results.sort(key=lambda r: r["path_score"], reverse=True)
        return results[:max_paths]

    def get_forest_dominance(self) -> Dict[str, Any]:
        all_domains = set(self._domain_index.keys())
        dominated: Set[str] = set()
        partially: Set[str] = set()

        for domain in all_domains:
            domain_t0 = {
                nid for nid in self._domain_index.get(domain, set()) if nid in self._tier0
            }
            if not domain_t0:
                continue
            reachable_t0: Set[str] = set()
            for owned in self._owned:
                reachable_t0 |= self.get_reachable_from(owned) & domain_t0

            if reachable_t0 >= domain_t0:
                dominated.add(domain)
            elif reachable_t0:
                partially.add(domain)

        return {
            "total_domains": len(all_domains),
            "dominated_domains": len(dominated),
            "partially_compromised": len(partially),
            "safe_domains": len(all_domains) - len(dominated) - len(partially),
            "dominated": list(dominated), "partial": list(partially),
            "full_forest_dominance": len(dominated) == len(all_domains) and len(all_domains) > 0,
        }

    def detect_laps_coverage(self) -> Dict[str, Any]:
        computers = [nid for nid, meta in self.entity_meta.items()
                     if self._type_of(nid) in ("COMPUTER", "DC")]
        laps_enabled = [nid for nid in computers if self.entity_meta[nid].get("laps_enabled")]
        laps_missing = [nid for nid in computers if not self.entity_meta[nid].get("laps_enabled")]

        dangerous_no_laps = []
        for nid in laps_missing:
            reachable = self.get_reachable_from(nid)
            if reachable & self._tier0:
                dangerous_no_laps.append({
                    "id": nid, "label": self._label_of(nid),
                    "tier0_reachable": len(reachable & self._tier0),
                })

        return {
            "total_computers": len(computers),
            "laps_enabled": len(laps_enabled), "laps_missing": len(laps_missing),
            "coverage_pct": round(len(laps_enabled) / max(len(computers), 1) * 100, 1),
            "dangerous_without_laps": len(dangerous_no_laps),
            "top_unprotected": sorted(dangerous_no_laps, key=lambda x: x["tier0_reachable"],
                                      reverse=True)[:10],
        }

    def detect_gmsa_exposure(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        read_edges = {"READ_GMSA_PASSWORD", "READ_DMSA_PASSWORD", "GMSA_PASSWORD"}
        for src, tgt, data in self.graph.edges(data=True):
            if data.get("edge_type", "").upper() in read_edges:
                reachable = self.get_reachable_from(tgt)
                t0 = list(reachable & self._tier0)
                if src not in self._tier0:
                    results.append({
                        "reader_id": src, "reader_label": self._label_of(src),
                        "gmsa_id": tgt, "gmsa_label": self._label_of(tgt),
                        "tier0_reachable": len(t0),
                        "risk_score": round(min(100, 70 + len(t0) * 5), 1),
                    })
        results.sort(key=lambda r: r["risk_score"], reverse=True)
        return results

    def detect_anomalies(self, days_back: int = 7) -> list:
        """Detect statistical outlier nodes and recent edge additions."""
        import statistics
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_back)
        results = []

        # Group nodes by entity type, compute degree z-score
        type_degrees: dict[str, list] = {}
        for n in self.graph.nodes():
            etype = self.entity_meta.get(n, {}).get("type", "UNKNOWN")
            deg = self.graph.out_degree(n)
            type_degrees.setdefault(etype, []).append((n, deg))

        for etype, node_degrees in type_degrees.items():
            if len(node_degrees) < 5:
                continue
            degrees = [d for _, d in node_degrees]
            mu = statistics.mean(degrees)
            try:
                sigma = statistics.stdev(degrees)
            except statistics.StatisticsError:
                continue
            if sigma == 0:
                continue
            for node_id, deg in node_degrees:
                z = (deg - mu) / sigma
                if z > 2.5:
                    results.append({
                        "node_id": node_id,
                        "node_label": self._label_of(node_id),
                        "node_type": etype,
                        "reason": "outlier_degree",
                        "z_score": round(z, 2),
                        "degree": deg,
                        "mean_degree": round(mu, 1),
                        "severity": "HIGH" if z > 3.5 else "MEDIUM",
                    })

        # Recent edges (first_seen_at within cutoff)
        for u, v, key, data in self.graph.edges(data=True, keys=True):
            first_seen = data.get("first_seen_at")
            if first_seen and isinstance(first_seen, datetime) and first_seen > cutoff:
                results.append({
                    "node_id": u,
                    "node_label": self._label_of(u),
                    "node_type": self.entity_meta.get(u, {}).get("type", "UNKNOWN"),
                    "reason": "recent_edge",
                    "edge_type": data.get("edge_type"),
                    "target_label": self._label_of(v),
                    "first_seen": first_seen.isoformat(),
                    "severity": "HIGH" if data.get("risk_weight", 0) >= 0.8 else "MEDIUM",
                })

        return sorted(results, key=lambda r: {"HIGH": 0, "MEDIUM": 1}.get(r["severity"], 2))[:50]

    def get_graph_stats(self) -> GraphStats:
        edge_type_breakdown: Dict[str, int] = defaultdict(int)
        for _, _, data in self.graph.edges(data=True):
            edge_type_breakdown[data.get("edge_type", "UNKNOWN")] += 1

        users = sum(1 for m in self.entity_meta.values()
                    if m.get("type") in ("USER", "SERVICE_ACCOUNT") and m.get("is_enabled", True))
        computers = sum(1 for m in self.entity_meta.values() if m.get("type") in ("COMPUTER", "DC"))
        groups = sum(1 for m in self.entity_meta.values() if m.get("type") == "GROUP")
        cas = sum(1 for m in self.entity_meta.values() if m.get("type") == "CA")
        domains = sum(1 for m in self.entity_meta.values() if m.get("type") in ("DOMAIN", "FOREST"))
        n = self.graph.number_of_nodes()
        e = self.graph.number_of_edges()
        avg_deg = round(e / max(n, 1), 2)
        density = round(nx.density(self.graph), 6) if n > 1 else 0.0

        try:
            undirected = self.graph.to_undirected()
            components = list(nx.connected_components(undirected))
            is_conn = len(components) == 1
            comp_count = len(components)
        except Exception:
            is_conn = False
            comp_count = 0

        return GraphStats(
            node_count=n, edge_count=e, tier0_count=len(self._tier0),
            enabled_user_count=users, computer_count=computers, group_count=groups,
            ca_count=cas, domain_count=domains, edge_type_breakdown=dict(edge_type_breakdown),
            avg_degree=avg_deg, density=density, is_connected=is_conn, component_count=comp_count,
        )

    def get_full_analytics(self) -> Dict[str, Any]:
        blast = self.compute_tier0_blast_radius()
        shadow = self.detect_shadow_admins()
        dcsync = self.detect_dcsync_principals()
        kerb = self.detect_kerberoastable_paths()
        asrep = self.detect_asrep_roastable()
        uncons = self.detect_unconstrained_delegation()
        cons = self.detect_constrained_delegation_abuse()
        rbcd = self.detect_rbcd_abuse()
        acl = self.detect_acl_abuse_paths(max_paths=20)
        adcs = self.detect_adcs_paths()
        laps = self.detect_laps_coverage()
        chokes = self.find_choke_points(top_n=10)
        stats = self.get_graph_stats()
        exposure = self.compute_exposure_surface()

        return {
            "stats": {
                "node_count": stats.node_count, "edge_count": stats.edge_count,
                "tier0_count": stats.tier0_count, "enabled_user_count": stats.enabled_user_count,
                "computer_count": stats.computer_count, "group_count": stats.group_count,
                "ca_count": stats.ca_count, "density": stats.density,
                "edge_type_breakdown": stats.edge_type_breakdown,
            },
            "blast_radius": {
                "non_tier0_nodes_that_can_reach_tier0": len(blast),
                "total_non_tier0": stats.node_count - stats.tier0_count,
                "reach_pct": round(len(blast) / max(stats.node_count - stats.tier0_count, 1) * 100, 1),
                "top_10": [
                    {"id": nid, "label": self._label_of(nid), "tier0_reach": cnt}
                    for nid, cnt in sorted(blast.items(), key=lambda x: x[1], reverse=True)[:10]
                ],
            },
            "exposure_surface": exposure,
            "shadow_admins": {
                "count": len(shadow),
                "items": [
                    {
                        "id": s.entity_id, "label": s.entity_label, "type": s.entity_type,
                        "control_paths": s.control_paths, "targets": len(s.targets),
                        "risk_score": s.risk_score,
                    }
                    for s in shadow[:10]
                ],
            },
            "dcsync_principals": {
                "count": len(dcsync),
                "unexpected_count": sum(1 for d in dcsync if not d["is_expected"]),
                "items": dcsync[:10],
            },
            "kerberoastable": {
                "count": len(kerb),
                "with_tier0_path": sum(1 for k in kerb if k["tier0_reachable"] > 0),
                "items": kerb[:10],
            },
            "asrep_roastable": {"count": len(asrep), "items": asrep[:10]},
            "delegation": {
                "unconstrained_count": len(uncons), "constrained_count": len(cons),
                "rbcd_count": len(rbcd),
                "unconstrained": [
                    {"id": d.entity_id, "label": d.entity_label,
                     "can_reach_tier0": d.can_reach_tier0, "risk": d.risk_score}
                    for d in uncons[:5]
                ],
            },
            "acl_abuse_paths": {
                "count": len(acl),
                "critical": sum(1 for p in acl if p.risk_level == "CRITICAL"),
                "items": [
                    {"from": p.source_label, "to": p.target_label,
                     "via": p.edge_types, "score": p.path_score}
                    for p in acl[:10]
                ],
            },
            "adcs": {
                "vulnerable_templates": len(adcs),
                "esc_types": list({p.esc_type for p in adcs}),
                "items": [
                    {"template": p.template_name, "ca": p.ca_name,
                     "esc": p.esc_type, "risk": p.risk_score}
                    for p in adcs[:10]
                ],
            },
            "laps": laps,
            "choke_points": [
                {
                    "id": c.node_id, "label": c.node_label, "type": c.node_type,
                    "is_articulation": c.is_articulation_point,
                    "paths_eliminated": c.attack_paths_through, "impact": c.remediation_impact,
                }
                for c in chokes
            ],
        }

    def export_for_frontend(
        self, max_nodes: int = 500, filter_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        blast = self.compute_tier0_blast_radius()
        direct_control_scores: Dict[str, float] = defaultdict(float)
        for src, tgt, edge_data in self.graph.edges(data=True):
            etype = edge_data.get("edge_type", "UNKNOWN")
            if etype not in CONTROL_EDGES:
                continue
            src_meta = self.entity_meta.get(src, {})
            if (
                src_meta.get("tier") == 0
                or src_meta.get("is_crown_jewel")
                or src_meta.get("is_admin_count")
            ):
                continue
            provenance = str(edge_data.get("provenance", "")).lower()
            if "direct" not in provenance and etype != "DCSYNC":
                continue
            risk = float(edge_data.get("risk_weight", EDGE_RISK.get(etype, 0.5)))
            direct_control_scores[src] = max(direct_control_scores[src], risk)
            direct_control_scores[tgt] = max(direct_control_scores[tgt], risk)

        bc_data = {}
        if self.graph.number_of_nodes() <= 2000:
            for item in self.compute_betweenness_centrality(top_n=100):
                bc_data[item["node_id"]] = item["betweenness_score"]

        def _priority(item: Tuple[str, dict]) -> Tuple:
            nid, meta = item
            tier = meta.get("tier") if meta.get("tier") is not None else 99
            return (
                0 if tier == 0 else (1 if tier == 1 else 2),
                0 if meta.get("is_crown_jewel") else 1,
                0 if nid in direct_control_scores else 1,
                -direct_control_scores.get(nid, 0.0),
                0 if meta.get("is_admin_count") else 1,
                -(blast.get(nid, 0)), self._label_of(nid).lower(), nid,
            )

        sorted_nodes = sorted(self.entity_meta.items(), key=_priority)
        nodes: List[dict] = []
        included: Set[str] = set()

        def _node_dict(nid: str, meta: dict) -> dict:
            return {
                "id": nid, "label": self._label_of(nid),
                "entity_type": meta.get("type", "UNKNOWN"),
                "tier": meta.get("tier"),
                "is_crown_jewel": bool(meta.get("is_crown_jewel")),
                "is_admin_count": bool(meta.get("is_admin_count")),
                "is_tier0": nid in self._tier0,
                "is_enabled": bool(meta.get("is_enabled", True)),
                "domain": meta.get("domain"),
                "tier0_reach": blast.get(nid, 0),
                "betweenness": round(bc_data.get(nid, 0.0), 6),
                "attributes": {
                    "has_spn": bool(meta.get("has_spn")),
                    "laps_enabled": bool(meta.get("laps_enabled")),
                    "uac_dont_req_preauth": bool(meta.get("uac_dont_req_preauth")),
                    "uac_trusted_for_deleg": bool(meta.get("uac_trusted_for_deleg")),
                    "uac_trusted_to_auth_deleg": bool(meta.get("uac_trusted_to_auth_deleg")),
                },
                "severity_count": self._get_node_finding_severity(nid),
            }

        # Phase 1: priority-ranked pass fills most of the budget.
        priority_budget = max(1, int(max_nodes * 0.85))
        for nid, meta in sorted_nodes:
            if filter_types and meta.get("type") not in filter_types:
                continue
            included.add(nid)
            nodes.append(_node_dict(nid, meta))
            if len(nodes) >= priority_budget:
                break

        # Phase 2: proportional per-type fill so every entity type is represented.
        # Reserve the remaining budget (~15%) and distribute evenly across types
        # that are under-represented or completely absent.
        remaining = max_nodes - len(nodes)
        if remaining > 0:
            # Group all unselected nodes by type
            type_pools: Dict[str, List[Tuple[str, dict]]] = defaultdict(list)
            for nid, meta in sorted_nodes:
                if nid in included:
                    continue
                if filter_types and meta.get("type") not in filter_types:
                    continue
                type_pools[meta.get("type", "UNKNOWN")].append((nid, meta))

            if type_pools:
                per_type = max(1, remaining // len(type_pools))
                for pool in type_pools.values():
                    for nid, meta in pool[:per_type]:
                        if len(nodes) >= max_nodes:
                            break
                        included.add(nid)
                        nodes.append(_node_dict(nid, meta))
                    if len(nodes) >= max_nodes:
                        break

        edges: List[dict] = []
        for src, tgt, key, data in self.graph.edges(data=True, keys=True):
            if src not in included or tgt not in included:
                continue
            etype = data.get("edge_type", "UNKNOWN")
            rw = data.get("risk_weight", EDGE_RISK.get(etype, 0.5))
            eid = key
            edges.append({
                "id": eid,
                "source": src, "target": tgt, "edge_type": etype,
                "risk_weight": round(float(rw), 3),
                "edge_confidence": data.get("edge_confidence", 1.0),
                "edge_provenance_type": data.get("edge_provenance_type", "collected"),
                "provenance": data.get("provenance", ""),
                "is_control_edge": etype in CONTROL_EDGES,
                "is_credential_edge": etype in CREDENTIAL_EDGES,
            })

        return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}

    def export_attack_subgraph(self) -> Dict[str, Any]:
        attack_g = self._get_attack_subgraph()
        nodes = []
        edges = []
        for nid in attack_g.nodes():
            meta = self.entity_meta.get(nid, {})
            nodes.append({
                "id": nid, "label": self._label_of(nid),
                "entity_type": meta.get("type", "UNKNOWN"),
                "tier": meta.get("tier"), "is_tier0": nid in self._tier0,
            })
        for src, tgt, data in attack_g.edges(data=True):
            edges.append({
                "id": f"{src[:8]}-{tgt[:8]}", "source": src, "target": tgt,
                "edge_type": data.get("edge_type", ""),
                "risk_weight": round(float(data.get("risk_weight", 0.5)), 3),
            })
        return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}

    def get_node_neighborhood(
        self, node_id: str, depth: int = 1, direction: str = "both",
    ) -> Dict[str, Any]:
        if node_id not in self.graph:
            return {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0}

        visited: Set[str] = {node_id}
        frontier: Set[str] = {node_id}

        for _ in range(depth):
            next_frontier: Set[str] = set()
            for nid in frontier:
                if direction in ("out", "both"):
                    next_frontier.update(self.graph.successors(nid))
                if direction in ("in", "both"):
                    next_frontier.update(self.graph.predecessors(nid))
            new = next_frontier - visited
            visited.update(new)
            frontier = new

        nodes = []
        edges = []
        for nid in visited:
            meta = self.entity_meta.get(nid, {})
            nodes.append({
                "id": nid, "label": self._label_of(nid),
                "entity_type": meta.get("type", "UNKNOWN"),
                "tier": meta.get("tier"),
                "is_crown_jewel": bool(meta.get("is_crown_jewel")),
                "is_tier0": nid in self._tier0, "is_focal": nid == node_id,
            })

        seen_edges: Set[Tuple[str, str]] = set()
        for src in visited:
            for tgt in self.graph.successors(src):
                if tgt in visited and (src, tgt) not in seen_edges:
                    seen_edges.add((src, tgt))
                    edge_data_map = self.graph.get_edge_data(src, tgt) or {}
                    # Use the highest-risk edge for display
                    data = max(edge_data_map.values(), key=lambda d: d.get("risk_weight", 0.5)) if edge_data_map else {}
                    edges.append({
                        "id": f"{src[:8]}-{tgt[:8]}", "source": src, "target": tgt,
                        "edge_type": data.get("edge_type", ""),
                        "risk_weight": round(float(data.get("risk_weight", 0.5)), 3),
                    })

        return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}

    def get_edge_type_statistics(self) -> List[Dict[str, Any]]:
        stats: Dict[str, int] = defaultdict(int)
        for _, _, data in self.graph.edges(data=True):
            stats[data.get("edge_type", "UNKNOWN")] += 1
        return sorted(
            [
                {
                    "edge_type": etype, "count": count,
                    "risk_weight": EDGE_RISK.get(etype, 0.5),
                    "category": _edge_category(etype),
                }
                for etype, count in stats.items()
            ],
            key=lambda x: (x["risk_weight"], x["count"]), reverse=True,
        )

    def _score_path(self, path: List[str]) -> float:
        if len(path) < 2:
            return 0.0

        edge_score = 0.0
        has_cred_edge = False
        has_deleg_edge = False

        for i in range(len(path) - 1):
            src, tgt = path[i], path[i + 1]
            data = self.graph.get_edge_data(src, tgt) or {}
            etype = data.get("edge_type", "")
            rw = _safe_float(data.get("risk_weight"), EDGE_RISK.get(etype, 0.5))
            edge_score += rw
            if etype in CREDENTIAL_EDGES:
                has_cred_edge = True
            if etype in {"ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT"}:
                has_deleg_edge = True

        hops = len(path) - 1
        avg_edge = edge_score / hops

        # Normalize: max possible avg edge score = 1.0 → 70 base points
        base = avg_edge * 70.0
        # Hop penalty: 1 hop = +20, 10 hops = 0
        hop_bonus = max(0.0, 20.0 * (1.0 - (hops - 1) / 10.0))
        target_bonus = 10.0 if path[-1] in self._tier0 else 0.0
        cj_bonus = 5.0 if self.entity_meta.get(path[-1], {}).get("is_crown_jewel") else 0.0
        cred_bonus = 8.0 if has_cred_edge else 0.0
        deleg_bonus = 5.0 if has_deleg_edge else 0.0

        raw = base + hop_bonus + target_bonus + cj_bonus + cred_bonus + deleg_bonus
        return round(min(100.0, raw), 2)

    def _risk_level_from_score(self, score: float) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 65:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"

    def _build_attack_path(self, path: List[str]) -> AttackPath:
        if len(path) < 2:
            return AttackPath(
                source_id=path[0] if path else "", target_id=path[-1] if path else "",
                source_label=self._label_of(path[0]) if path else "",
                target_label=self._label_of(path[-1]) if path else "",
                hop_count=0, path_score=0.0, risk_level="LOW",
                node_ids=list(path), edge_types=[],
            )

        steps: List[PathStep] = []
        edge_types: List[str] = []
        involves_cred = involves_deleg = involves_adcs = crosses_trust = False

        for i, nid in enumerate(path):
            meta = self.entity_meta.get(nid, {})
            step = PathStep(
                node_id=nid, node_label=self._label_of(nid), node_type=self._type_of(nid),
                tier=meta.get("tier"), is_crown_jewel=bool(meta.get("is_crown_jewel")),
            )
            if i < len(path) - 1:
                nxt = path[i + 1]
                _raw_edge_data = self.graph.get_edge_data(nid, nxt) or {}
                # MultiDiGraph returns {key: data_dict}; pick the highest-risk edge
                if _raw_edge_data:
                    data = max(_raw_edge_data.values(), key=lambda d: d.get("risk_weight", 0))
                else:
                    data = {}
                etype = data.get("edge_type", "UNKNOWN")
                rw = _safe_float(data.get("risk_weight"), EDGE_RISK.get(etype, 0.5))
                step.edge_type = etype
                step.edge_risk = rw
                step.edge_provenance = data.get("provenance")
                step.explanation = _explain_edge(etype, self._label_of(nid), self._label_of(nxt))
                edge_types.append(etype)
                if etype in CREDENTIAL_EDGES:
                    involves_cred = True
                if etype in {"ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT"}:
                    involves_deleg = True
                if etype == "CAN_ENROLL":
                    involves_adcs = True
                if etype == "TRUSTS":
                    crosses_trust = True
            steps.append(step)

        # Collect per-hop edge confidence and risk weights (MultiDiGraph: pick best edge per pair)
        step_risks: List[float] = []
        edge_confidences: List[float] = []
        for u, v in zip(path[:-1], path[1:]):
            edge_data = self.graph.get_edge_data(u, v)
            if edge_data:
                best = max(edge_data.values(), key=lambda d: d.get("risk_weight", 0))
                step_risks.append(float(best.get("risk_weight", 0.5)))
                edge_confidences.append(float(best.get("edge_confidence", 1.0)))
        avg_risk = sum(step_risks) / max(len(step_risks), 1)
        confidence = min(edge_confidences) if edge_confidences else 1.0

        # Improved path score formula
        hop_count = len(path) - 1
        tier0_proximity = 1.0 if any(self.is_tier0(n) for n in path[1:]) else 0.5
        raw_score = (
            avg_risk * 0.40
            + (1.0 / max(hop_count, 1)) * 0.20
            + tier0_proximity * 0.20
            + (0.10 if involves_cred else 0.0)
            + (0.10 if involves_deleg else 0.0)
        )
        path_score = round(min(raw_score, 1.0) * 100, 2)

        # Cap score by confidence
        if confidence < 0.5:
            path_score = min(path_score, 70.0)
        elif confidence < 0.8:
            path_score = min(path_score, 85.0)

        src = path[0]
        tgt = path[-1]
        return AttackPath(
            source_id=src, target_id=tgt,
            source_label=self._label_of(src), target_label=self._label_of(tgt),
            hop_count=hop_count, path_score=path_score,
            risk_level=self._risk_level_from_score(path_score),
            steps=steps, node_ids=list(path), edge_types=edge_types,
            involves_credential_access=involves_cred, involves_delegation=involves_deleg,
            involves_adcs=involves_adcs, crosses_trust=crosses_trust,
            explanation=_build_explanation(steps),
            confidence=confidence,
        )

    def _pathresult_to_attackpath(self, pr: PathResult) -> AttackPath:
        return self._build_attack_path(pr.path)

    def _build_path_result(self, path: List[str]) -> PathResult:
        edge_types: List[str] = []
        for i in range(len(path) - 1):
            data = self.graph.get_edge_data(path[i], path[i + 1]) or {}
            edge_types.append(data.get("edge_type", "UNKNOWN"))

        score = self._score_path(path)
        explanation = _build_explanation_simple(path, edge_types, self.entity_meta)

        return PathResult(
            source_id=path[0], target_id=path[-1], path=list(path),
            edge_types=edge_types, hop_count=len(path) - 1,
            path_score=score, explanation=explanation,
        )

    def _get_attack_subgraph(self) -> nx.DiGraph:
        if not self._tier0:
            return self.graph

        on_path: Set[str] = set(self._tier0)
        rev = self.graph.reverse(copy=False)
        for t0 in self._tier0:
            if t0 in rev:
                on_path.update(nx.descendants(rev, t0))

        return self.graph.subgraph(on_path).copy()

    def _count_paths_to_tier0(self, graph: Optional[nx.DiGraph] = None) -> int:
        g = graph if graph is not None else self.graph
        tier0 = self._tier0

        reachable: Set[str] = set()
        rev = g.reverse(copy=False)
        for t0 in tier0:
            if t0 in rev:
                try:
                    reachable.update(nx.descendants(rev, t0))
                except nx.NodeNotFound:
                    pass
        return len(reachable - tier0)

    def _get_node_finding_severity(self, node_id: str) -> Dict[str, int]:
        attrs = self.entity_meta.get(node_id, {}).get("attributes", {}) or {}
        return attrs.get("severity_count", {})

    def get_unconstrained_delegation_exposure(self) -> List[str]:
        return [d.entity_id for d in self.detect_unconstrained_delegation()]


def _explain_edge(edge_type: str, src_label: str, tgt_label: str) -> str:
    explanations: Dict[str, str] = {
        "GENERIC_ALL":            "{src} has GenericAll over {tgt} — full object control",
        "WRITE_DACL":             "{src} can modify the DACL of {tgt} — grant any right",
        "WRITE_OWNER":            "{src} can take ownership of {tgt} → then modify DACL",
        "OWNS":                   "{src} owns {tgt} — implicit full control",
        "FORCE_CHANGE_PASSWORD":  "{src} can reset the password of {tgt} without knowing it",
        "ADD_MEMBER":             "{src} can add members to {tgt} — escalate via group membership",
        "MEMBER_OF":              "{src} is a member of {tgt} — inherits group privileges",
        "DCSYNC":                 "{src} has DCSync rights on {tgt} — dump all credentials",
        "ALLOWED_TO_DELEGATE":    "{src} has constrained delegation to {tgt} — impersonate users",
        "ALLOWED_TO_ACT":         "{src} has RBCD configured on {tgt} — impersonate any user",
        "ADMIN_TO":               "{src} is admin on {tgt}",
        "LOCAL_ADMIN":            "{src} has local admin on {tgt}",
        "CAN_RDP":                "{src} can RDP into {tgt}",
        "CAN_WINRM":              "{src} can WinRM into {tgt}",
        "HAS_SPN":                "{src} has an SPN registered on {tgt} — Kerberoastable",
        "CAN_ENROLL":             "{src} can enroll in certificate template {tgt}",
        "TRUSTS":                 "{src} trusts {tgt} — authentication may flow across boundary",
        "CONTAINS":               "{tgt} is contained within OU/domain {src}",
        "APPLIES_GPO":            "GPO {src} applies to {tgt}",
        "HAS_CONTROL":            "{src} has control over {tgt}",
    }
    template = explanations.get(edge_type, f"{{src}} —[{edge_type}]→ {{tgt}}")
    return template.format(src=src_label, tgt=tgt_label)


def _build_explanation(steps: List[PathStep]) -> str:
    if not steps:
        return ""
    parts: List[str] = []
    for step in steps:
        if step.edge_type:
            parts.append(step.explanation or f"{step.node_label} —[{step.edge_type}]→")
        else:
            parts.append(step.node_label)
    return " ".join(parts)


def _build_explanation_simple(
    path: List[str], edge_types: List[str], entity_meta: Dict[str, dict],
) -> str:
    def _label(nid: str) -> str:
        m = entity_meta.get(nid, {})
        return m.get("sam_account_name") or m.get("display_name") or nid[:12]

    parts: List[str] = []
    for i, nid in enumerate(path):
        etype = entity_meta.get(nid, {}).get("type", "?")
        label = _label(nid)
        if i < len(edge_types):
            edge = edge_types[i].replace("_", " ").title()
            parts.append(f"{label} ({etype}) —[{edge}]→")
        else:
            parts.append(f"{label} ({etype})")
    return " ".join(parts)


def _edge_category(edge_type: str) -> str:
    if edge_type in {"GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS"}:
        return "acl_abuse"
    if edge_type in {"DCSYNC", "FORCE_CHANGE_PASSWORD"}:
        return "credential_access"
    if edge_type in {"ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT"}:
        return "delegation"
    if edge_type in {"MEMBER_OF", "ADD_MEMBER"}:
        return "group_membership"
    if edge_type in {"ADMIN_TO", "LOCAL_ADMIN", "CAN_RDP", "CAN_WINRM"}:
        return "lateral_movement"
    if edge_type == "CAN_ENROLL":
        return "adcs"
    if edge_type == "TRUSTS":
        return "domain_trust"
    if edge_type in {"CONTAINS", "APPLIES_GPO"}:
        return "structure"
    return "other"


def _remediation_for_edge(edge_type: str, src: str, tgt: str) -> str:
    remediations: Dict[str, str] = {
        "GENERIC_ALL":            f"Remove GenericAll ACE from {src} on {tgt}",
        "WRITE_DACL":             f"Remove WriteDACL ACE from {src} on {tgt}",
        "WRITE_OWNER":            f"Remove WriteOwner ACE from {src} on {tgt}",
        "OWNS":                   f"Change ownership of {tgt} away from {src}",
        "FORCE_CHANGE_PASSWORD":  f"Remove ForceChangePassword right from {src} over {tgt}",
        "ADD_MEMBER":             f"Remove AddMember right from {src} on group {tgt}",
        "DCSYNC":                 f"Revoke DCSync rights for {src} on {tgt}",
        "ALLOWED_TO_DELEGATE":    f"Remove delegation configuration from {src} targeting {tgt}",
        "ALLOWED_TO_ACT":         f"Clear msDS-AllowedToActOnBehalfOfOtherIdentity on {tgt}",
        "ADMIN_TO":               f"Remove {src} from local Administrators on {tgt}",
        "LOCAL_ADMIN":            f"Remove {src} from local Administrators on {tgt}",
        "CAN_ENROLL":             f"Restrict enrollment rights on template; remove {src}",
    }
    return remediations.get(
        edge_type, f"Review and remove {edge_type} relationship from {src} to {tgt}",
    )


_REMEDIATION_STEPS: Dict[str, List[str]] = {
    "GENERIC_ALL": [
        "Open ADUC → right-click {tgt} → Properties → Security",
        "Locate {src} in the ACL list",
        "Uncheck 'Full Control' (GenericAll) — apply least-privilege ACE only",
        "Run: Get-ObjectAcl -Identity '{tgt}' | ? {{$_.ActiveDirectoryRights -eq 'GenericAll'}} to verify removal",
    ],
    "WRITE_DACL": [
        "Open ADUC → right-click {tgt} → Properties → Security → Advanced",
        "Find the ACE granting WriteDACL to {src}",
        "Remove or scope down the ACE to deny DACL modification",
        "Enable 'Protect object from accidental deletion' as defence-in-depth",
        "Audit via: Get-ObjectAcl -Identity '{tgt}' | ? {{$_.ActiveDirectoryRights -match 'WriteDacl'}}",
    ],
    "WRITE_OWNER": [
        "Identify current owner: Get-ADObject '{tgt}' -Properties nTSecurityDescriptor",
        "Transfer ownership to a protected admin account or the Domain Admins group",
        "Remove WriteOwner ACE from {src} in the object's DACL",
        "Verify: (Get-Acl 'AD:\\{tgt}').Owner",
    ],
    "OWNS": [
        "Change object owner: Set-ADObject '{tgt}' -Replace @{{nTSecurityDescriptor=...}} or use ADSI Edit",
        "Assign ownership to a break-glass admin account that is not {src}",
        "Remove any residual Full Control ACEs inherited from ownership",
    ],
    "FORCE_CHANGE_PASSWORD": [
        "Open ADUC → right-click {tgt} → Properties → Security",
        "Remove 'Reset Password' ACE granted to {src}",
        "Confirm removal: Get-ObjectAcl '{tgt}' | ? {{$_.ObjectAceType -eq 'User-Force-Change-Password'}}",
        "Rotate the password of {tgt} immediately as a precaution",
    ],
    "ADD_MEMBER": [
        "Remove AddMember ACE: ADUC → {tgt} → Security → remove Write Members permission for {src}",
        "Audit current members of {tgt}: Get-ADGroupMember -Identity '{tgt}'",
        "Review and remove any unauthorized members already added",
        "Enable group membership auditing (Event ID 4728/4732)",
    ],
    "DCSYNC": [
        "Identify the offending ACE: (Get-ObjectAcl (Get-ADDomain).DistinguishedName -ResolveGUIDs) | ? {{$_.ObjectAceType -match 'Replication'}}",
        "Remove DS-Replication-Get-Changes and DS-Replication-Get-Changes-All from {src}",
        "Use: Remove-DomainObjectAcl -TargetIdentity '{tgt}' -PrincipalIdentity '{src}' -Rights DCSync",
        "Rotate krbtgt password twice (48h apart) to invalidate any stolen hashes",
        "Monitor for subsequent DCSync attempts: Event ID 4662 with Properties {1131f6aa-...}",
    ],
    "ALLOWED_TO_DELEGATE": [
        "Set-ADComputer {src} -TrustedForDelegation $false  (unconstrained) or",
        "Set-ADUser {src} -TrustedForDelegation $false  for user accounts",
        "For constrained delegation: remove SPN from msDS-AllowedToDelegateTo on {src}",
        "Ensure {src} account has 'Account is sensitive and cannot be delegated' checked if it is a service account",
    ],
    "ALLOWED_TO_ACT": [
        "Clear RBCD attribute: Set-ADComputer '{tgt}' -PrincipalsAllowedToDelegateToAccount $null",
        "Verify: Get-ADComputer '{tgt}' -Properties msDS-AllowedToActOnBehalfOfOtherIdentity",
        "If {src} was added maliciously, rotate the machine account password of {tgt}",
    ],
    "ADMIN_TO": [
        "On {tgt}: net localgroup Administrators /delete '{src}'  (or via GPO/LAPS)",
        "Use Restricted Groups GPO to enforce local admin membership",
        "Enable LAPS on {tgt} to rotate the local administrator password automatically",
        "Audit: Invoke-Command -ComputerName {tgt} -ScriptBlock {{net localgroup Administrators}}",
    ],
    "LOCAL_ADMIN": [
        "Remove {src} from local Administrators: net localgroup Administrators '{src}' /delete",
        "Deploy LAPS or Microsoft Defender Credential Guard on {tgt}",
        "Review GPO Restricted Groups policy for {tgt}",
    ],
    "CAN_ENROLL": [
        "Open certsrv.msc → Certificate Templates → right-click template → Properties → Security",
        "Remove Enroll/AutoEnroll permission for {src}",
        "Consider requiring Manager Approval on the template as a compensating control",
        "Audit issued certificates: certutil -view -out 'RequesterName,CertificateTemplate'",
    ],
    "PASS_THE_HASH": [
        "Enable Credential Guard on {src} (requires UEFI Secure Boot + Virtualization Based Security)",
        "Restrict {src} from logging into machines where {tgt} credentials are cached",
        "Deploy Protected Users security group for {tgt} (disables NTLM auth)",
        "Enforce unique local admin passwords via LAPS",
    ],
    "PASS_THE_TICKET": [
        "Enrol {tgt} in the Protected Users group to block Kerberos ticket caching",
        "Set 'Account is sensitive and cannot be delegated' on {tgt}",
        "Reduce Kerberos ticket lifetime: Set-ADDefaultDomainPasswordPolicy -MaxTicketAge 8:00:00",
        "Monitor for Kerberos TGT requests from unexpected hosts: Event ID 4769",
    ],
    "KERBEROAST": [
        "Rotate the Kerberos service account password for {tgt} to a random 128-character string",
        "Remove unnecessary SPNs: Set-ADUser '{tgt}' -ServicePrincipalNames @{{Remove='<SPN>'}}",
        "Migrate the service to a Group Managed Service Account (gMSA) — auto-rotating password",
        "Enable AES256 encryption for {tgt}: Set-ADUser '{tgt}' -KerberosEncryptionType AES256",
    ],
    "ASREP_ROAST": [
        "Enable Kerberos pre-authentication: Set-ADUser '{tgt}' -DoesNotRequirePreAuth $false",
        "Rotate {tgt} password immediately (AS-REP hash may already be captured)",
        "Audit accounts with pre-auth disabled: Get-ADUser -Filter {{DoesNotRequirePreAuth -eq $true}}",
    ],
}


def _remediation_steps_for_edge(edge_type: str, src: str, tgt: str) -> List[str]:
    template = _REMEDIATION_STEPS.get(edge_type)
    if template:
        return [step.replace("{src}", src).replace("{tgt}", tgt) for step in template]
    return [f"Audit and remove the {edge_type} relationship between {src} and {tgt} following your organisation's AD hardening baseline"]
