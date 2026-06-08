from __future__ import annotations
from collections import deque
from adbygod_api.core.validation.contracts import BlastRadiusResult


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _value(obj):
    return _get(obj, 'value', obj)


class BlastRadiusEngine:
    def compute(
        self,
        origin_entity_id: str,
        ctx,
        max_hops: int = 6,
    ) -> BlastRadiusResult:
        # Build adjacency from ctx.edges
        edges = getattr(ctx, 'edges', [])
        entities = getattr(ctx, 'entities', [])
        tier0_ids = set(getattr(ctx, 'tier0_entities', []))

        # Build id→entity map
        entity_map: dict[str, dict] = {}
        for e in entities:
            if isinstance(e, dict):
                eid = str(e.get('id', ''))
                if eid:
                    entity_map[eid] = e
            else:
                eid = str(getattr(e, 'id', ''))
                if eid:
                    entity_type = _value(getattr(e, 'entity_type', getattr(e, 'type', '')))
                    attrs = getattr(e, 'attributes', {}) or {}
                    entity_map[eid] = {
                        'id': eid,
                        'type': entity_type,
                        'name': str(getattr(e, 'name', getattr(e, 'sam_account_name', getattr(e, 'display_name', '')))),
                        'properties': attrs,
                    }

        # Build adjacency list (directed: follow attack edges)
        adj: dict[str, list[str]] = {}
        attack_edge_types = {
            'GenericAll', 'GenericWrite', 'WriteDACL', 'WriteOwner', 'WriteProperty',
            'AllExtendedRights', 'ForceChangePassword', 'AddMember', 'AddSelf',
            'DCSync', 'GetChanges', 'GetChangesAll', 'ReadLAPSPassword',
            'AllowedToDelegate', 'AllowedToAct', 'OwnsObject',
            'Contains', 'MemberOf', 'HasSession',
        }
        normalized_attack_edge_types = {etype.replace('_', '').lower() for etype in attack_edge_types}
        for edge in edges:
            if isinstance(edge, dict):
                rel = edge.get('relationship_type', edge.get('type', ''))
                src = str(edge.get('source_id', edge.get('source', '')))
                tgt = str(edge.get('target_id', edge.get('target', '')))
            else:
                rel = str(getattr(edge, 'relationship_type', '') or _value(getattr(edge, 'edge_type', '')))
                src = str(getattr(edge, 'source_id', ''))
                tgt = str(getattr(edge, 'target_id', ''))

            normalized_rel = rel.replace('_', '').lower()
            if normalized_rel in normalized_attack_edge_types or not rel:
                adj.setdefault(src, []).append(tgt)

        # BFS from origin
        visited: set[str] = {origin_entity_id}
        queue: deque[tuple[str, int]] = deque([(origin_entity_id, 0)])
        critical_paths: list[list[str]] = []

        counters = {
            'computers': 0, 'dcs': 0, 'domains': 0,
            'ous': 0, 'groups': 0, 'users': 0,
        }
        tier0_reachable = False

        while queue:
            node_id, hop = queue.popleft()
            if hop >= max_hops:
                continue

            for neighbor in adj.get(node_id, []):
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                queue.append((neighbor, hop + 1))

                # Classify neighbor
                ent = entity_map.get(neighbor, {})
                ent_type = str(ent.get('type', '')).lower()
                props = ent.get('properties', {}) or {}
                if 'domaincontroller' in ent_type or 'domain_controller' in ent_type or props.get('isdc', False) or props.get('isDC', False):
                    counters['dcs'] += 1
                    if hop <= 3:
                        critical_paths.append([origin_entity_id, '...', neighbor])
                elif 'computer' in ent_type:
                    counters['computers'] += 1
                elif 'domain' in ent_type:
                    counters['domains'] += 1
                elif 'ou' in ent_type or 'organizational' in ent_type:
                    counters['ous'] += 1
                elif 'group' in ent_type:
                    counters['groups'] += 1
                elif 'user' in ent_type:
                    counters['users'] += 1

                if neighbor in tier0_ids:
                    tier0_reachable = True
                    if len(critical_paths) < 5:
                        critical_paths.append([origin_entity_id, '...', neighbor, '(TIER-0)'])

        total = sum(counters.values())
        # If edge data is sparse, estimate from findings/context
        if total == 0 and len(visited) > 1:
            total = len(visited) - 1

        return BlastRadiusResult(
            origin_entity_id=origin_entity_id,
            reachable_computers=counters['computers'],
            reachable_domain_controllers=counters['dcs'],
            reachable_domains=counters['domains'],
            reachable_ous=counters['ous'],
            reachable_groups=counters['groups'],
            reachable_users=counters['users'],
            total_reachable=total,
            tier0_reachable=tier0_reachable,
            critical_paths=[' → '.join(p) for p in critical_paths[:5]],
        )
