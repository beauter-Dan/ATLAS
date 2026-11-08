"""Architecture mapper. Every edge carries evidence_id + confidence."""
import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import Asset, Evidence, Relationship

ZONES = {"domain": "public_internet", "subdomain": "public_internet", "ip": "public_internet", "url": "public_internet",
         "api": "application", "application_server": "application", "service": "application",
         "auth_system": "application", "database": "data", "storage": "data", "third_party": "external_third_party"}
CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def _zone(asset_type: str) -> str:
    return ZONES.get(asset_type, "unknown")


def build_relationships(db: Session, assessment_id: str) -> int:
    """Derive relationships from structured 'links' stored in evidence payloads."""
    created = 0
    for ev in db.scalars(select(Evidence).where(Evidence.assessment_id == assessment_id)).all():
        for ln in (ev.payload or {}).get("links", []):
            (ta, va), (tb, vb) = ln["from"], ln["to"]
            a = db.scalar(select(Asset).where(Asset.assessment_id == assessment_id, Asset.asset_type == ta, Asset.value == va.lower()))
            b = db.scalar(select(Asset).where(Asset.assessment_id == assessment_id, Asset.asset_type == tb, Asset.value == vb.lower()))
            if not a or not b:
                continue
            exists = db.scalar(select(Relationship).where(
                Relationship.assessment_id == assessment_id, Relationship.source_asset_id == a.id,
                Relationship.target_asset_id == b.id, Relationship.relation_type == ln["relation"]))
            if exists:
                continue
            db.add(Relationship(assessment_id=assessment_id, source_asset_id=a.id, target_asset_id=b.id,
                                relation_type=ln["relation"], evidence_id=ev.id, confidence=ev.confidence,
                                crosses_trust_boundary=_zone(a.asset_type) != _zone(b.asset_type)))
            created += 1
    db.flush()
    return created


def graph(db: Session, assessment_id: str) -> dict:
    assets = db.scalars(select(Asset).where(Asset.assessment_id == assessment_id)).all()
    rels = db.scalars(select(Relationship).where(Relationship.assessment_id == assessment_id)).all()
    g = nx.DiGraph()
    for a in assets:
        g.add_node(a.id, type=a.asset_type, value=a.value, scope_state=a.scope_state, zone=_zone(a.asset_type))
    for r in rels:
        g.add_edge(r.source_asset_id, r.target_asset_id, relation=r.relation_type, evidence_id=r.evidence_id,
                   confidence=r.confidence, crosses=r.crosses_trust_boundary, id=r.id)
    nodes = [{"id": n, **d} for n, d in g.nodes(data=True)]
    edges = [{"id": d["id"], "source": u, "target": v, "relation": d["relation"], "evidence_id": d["evidence_id"],
              "confidence": d["confidence"], "crosses_trust_boundary": d["crosses"]} for u, v, d in g.edges(data=True)]
    zones: dict[str, list[str]] = {}
    for n in nodes:
        zones.setdefault(n["zone"], []).append(n["id"])
    return {"nodes": nodes, "edges": edges,
            "trust_boundaries": [{"from_zone": g.nodes[e["source"]]["zone"], "to_zone": g.nodes[e["target"]]["zone"],
                                  "edge_id": e["id"], "evidence_id": e["evidence_id"]} for e in edges if e["crosses_trust_boundary"]],
            "zones": zones,
            "stats": {"nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
                      "weakly_connected_components": nx.number_weakly_connected_components(g) if g.number_of_nodes() else 0}}
