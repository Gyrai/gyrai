"""Evidence engine. Turns the audit store + inventory into control narratives.

Honesty rule: a control only gets the narrative its observation level earns. If the
strongest data we have for a control is metadata_only, the 'enforced' narrative is
never emitted, and the report says so. This is what keeps the product defensible in
front of an assessor.
"""
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import AISystem, AuditEvent
from .ingest import verify_chain

MAPPINGS_DIR = Path(__file__).resolve().parents[2] / "evidence" / "mappings"
LEVEL_RANK = {"metadata_only": 0, "content_visible": 1, "enforced": 2}


def load_mapping(name: str = "nist-800-171r2") -> dict:
    """Load a control mapping from evidence/mappings/<name>.yaml. To support another
    framework, add a file there that follows the same structure."""
    return yaml.safe_load((MAPPINGS_DIR / f"{name}.yaml").read_text())


def _facts(db: Session) -> dict:
    """Every number a narrative template can reference. Computed once per report."""
    systems = db.scalars(select(AISystem)).all()
    total = db.scalar(select(func.count(AuditEvent.seq))) or 0
    first = db.scalar(select(func.min(AuditEvent.timestamp)))
    last = db.scalar(select(func.max(AuditEvent.timestamp)))
    dlp_rows = db.scalars(select(AuditEvent).where(AuditEvent.dlp_hit.is_(True))).all()
    # "External" means hosted outside the organization, such as a public SaaS service.
    external_keys = {s.key for s in systems if s.hosting == "external_saas"}
    attributed = db.scalar(
        select(func.count(AuditEvent.seq)).where(AuditEvent.actor_id.is_not(None), AuditEvent.actor_id != "")
    ) or 0
    external_events = db.scalar(
        select(func.count(AuditEvent.seq)).where(AuditEvent.ai_system.in_(external_keys))
    ) if external_keys else 0
    # Counts events whose recorded decision was block or mask. In monitor mode those decisions were advisory: nothing was actually blocked.
    blocked = db.scalar(
        select(func.count(AuditEvent.seq)).where(AuditEvent.decision_action.in_(["block", "mask"]))
    ) or 0
    sources = db.execute(select(AuditEvent.source).distinct()).scalars().all()
    chain = verify_chain(db)

    def fmt(dt: datetime | None) -> str:
        return dt.strftime("%Y-%m-%d") if dt else "n/a"

    return {
        "product": settings.product_name,
        "org": settings.org_name,
        "schema_version": "1.0.0",
        "total_events": total,
        "first_event": fmt(first),
        "last_event": fmt(last),
        "dlp_count": len(dlp_rows),
        "dlp_systems": len({r.ai_system for r in dlp_rows}),
        "external_dlp_count": sum(1 for r in dlp_rows if r.ai_system in external_keys),
        "blocked_count": blocked,
        "system_count": len(systems),
        "governed_count": sum(1 for s in systems if s.governance_state == "governed"),
        "observed_count": sum(1 for s in systems if s.governance_state == "observed"),
        "declared_count": sum(1 for s in systems if s.governance_state == "declared"),
        "external_count": len(external_keys),
        "unapproved_count": sum(1 for s in systems if not s.approved),
        "external_event_count": external_events or 0,
        "attributed_pct": round(100 * attributed / total) if total else 0,
        "source_count": len(sources),
        "chain_status": "VERIFIED, %d records" % chain["checked"] if chain["ok"] else "BROKEN at record %s" % chain.get("broken_at_seq"),
        "_systems": systems,
    }


def _max_level_for(db: Session, event_types: list[str]) -> str | None:
    """The strongest observation level seen among events of these types, or None if there are
    none. "*" matches every event type."""
    q = select(AuditEvent.observation_level).distinct()
    if "*" not in event_types:
        q = q.where(AuditEvent.event_type.in_(event_types))
    levels = db.execute(q).scalars().all()
    if not levels:
        return None
    return max(levels, key=lambda l: LEVEL_RANK[l])


def build_report(db: Session, framework: str = "nist-800-171r2") -> dict:
    """Build the evidence report as a dict (the JSON API and the Markdown export both use it).

    For each control in the mapping, pick the strongest evidence rule whose minimum observation
    level is met by data actually in the store, and fill its narrative template with real
    numbers from _facts(). A control with no qualifying data is reported as "no_evidence_yet"
    rather than given a weaker-sounding narrative.
    """
    mapping = load_mapping(framework)
    facts = _facts(db)
    controls_out = []
    for ctl in mapping["controls"]:
        best = None
        for ev in ctl["evidence"]:
            have = _max_level_for(db, ev["events"])
            if have is None:
                continue
            # A rule applies only if we hold events at least as strong as it requires. Weaker data never earns the stronger narrative.
            if LEVEL_RANK[have] >= LEVEL_RANK[ev["min_level"]]:
                # Collapse the YAML's line breaks, then fill the {placeholders} with real numbers from _facts().
                cand = {
                    "strength": ev["strength"],
                    "observation_level": have,
                    "narrative": " ".join(ev["narrative"].split()).format(**facts),
                }
                if best is None or LEVEL_RANK[have] > LEVEL_RANK[best["observation_level"]]:
                    best = cand
        controls_out.append({
            "id": ctl["id"],
            "name": ctl["name"],
            "family": ctl["family"],
            "also_800_53": ctl.get("also_800_53", []),
            "ai_rmf": ctl.get("ai_rmf", []),
            "status": "evidence_available" if best else "no_evidence_yet",
            **(best or {}),
        })
    # Appendix A: systems nobody has approved (the "shadow AI" list).
    shadow = [
        {"key": s.key, "display_name": s.display_name, "hosting": s.hosting,
         "first_seen": s.first_seen.isoformat(), "event_count": s.event_count, "sources": s.sources}
        for s in facts["_systems"] if not s.approved
    ]
    return {
        "framework": framework,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "organization": facts["org"],
        "product": facts["product"],
        "summary": {k: v for k, v in facts.items() if not k.startswith("_")},
        "controls": controls_out,
        "appendix_a_shadow_ai": shadow,
    }


def report_markdown(report: dict) -> str:
    """Render a report from build_report() as a Markdown document an assessor can read."""
    s = report["summary"]
    lines = [
        f"# AI Governance Evidence Report — {report['organization']}",
        "",
        "Framework: NIST SP 800-171 Rev 2 (CMMC Level 2)  ",
        f"Generated: {report['generated_at']}  ",
        f"Generated by: {report['product']}",
        "",
        "## Summary",
        "",
        f"- Audit records: **{s['total_events']}** ({s['first_event']} to {s['last_event']})",
        f"- AI systems in inventory: **{s['system_count']}** — {s['governed_count']} governed, "
        f"{s['observed_count']} observed, {s['declared_count']} declared",
        f"- Externally hosted: {s['external_count']}; without recorded approval: **{s['unapproved_count']}**",
        f"- Events with flagged content (CUI/ITAR/PII markers): **{s['dlp_count']}**",
        f"- Audit chain integrity: {s['chain_status']}",
        "",
        "## Control Narratives",
        "",
        "Evidence strength reflects what this product can demonstrate from its own data. "
        "*full* = objective demonstrated; *partial* = supports the objective, other artifacts required; "
        "*observe* = visibility only.",
        "",
    ]
    for c in report["controls"]:
        lines.append(f"### {c['id']} {c['name']}")
        lines.append(f"*Family: {c['family']} · 800-53: {', '.join(c['also_800_53'])} · AI RMF: {', '.join(c['ai_rmf'])}*")
        lines.append("")
        if c["status"] == "evidence_available":
            lines.append(f"**Evidence strength: {c['strength']}** (observation level: {c['observation_level']})")
            lines.append("")
            lines.append(c["narrative"])
        else:
            lines.append("_No evidence collected yet for this control. Connect a source that produces the required events._")
        lines.append("")
    lines += ["## Appendix A — AI Systems Without Recorded Approval", ""]
    if report["appendix_a_shadow_ai"]:
        lines.append("| System | Hosting | First seen | Events | Sources |")
        lines.append("|---|---|---|---|---|")
        for sh in report["appendix_a_shadow_ai"]:
            lines.append(f"| {sh['display_name']} | {sh['hosting']} | {sh['first_seen'][:10]} | {sh['event_count']} | {', '.join(sh['sources'])} |")
    else:
        lines.append("_None._")
    lines.append("")
    return "\n".join(lines)
