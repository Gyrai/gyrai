# AI Control Plane — policy bundle
#
# Evaluated on every ingested event. Today the result is ADVISORY: it is recorded
# in the event's `decision` block with mode="monitor" and nothing is blocked.
# When the inline gateway ships, the same rules run with mode="enforce" and the
# `action` becomes binding. One policy, two modes.
#
# Query:  POST /v1/data/aicp/advisory   {"input": <audit event>}
# Result: {"mode": "monitor", "action": "block|mask|require_approval|route_local|allow",
#          "policy_id": "...", "policy_version": "...", "reason": "..."}

package aicp

import rego.v1

# Set from CI at build time; shows up in every decision (CM-3 change control).
policy_version := "dev"

# ---- Reference data (move to data.json per customer) ----

# AI systems the organization has approved for CUI. Everything else is "no CUI".
cui_approved_systems := {"m365.copilot", "internal.rag-assistant"}

# Tools an agent may call without a human approving each call.
auto_approved_tools := {"query_maintenance_db", "fetch_public_regulations", "search_docs"}

# Tools that can never be called by an agent in this environment.
forbidden_tools := {"delete_records", "transfer_funds"}

# ---- Helpers ----

external if input.target.hosting == "external_saas"

has_finding(cat) if {
	some f in input.content.dlp_findings
	f.category == cat
}

cui_like if has_finding("CUI_MARKING")

cui_like if has_finding("DISTRIBUTION_STATEMENT")

cui_like if has_finding("ITAR_TERM")

is_tool_call if input.event_type == "ai.tool.called"

# ---- Rules. Lower priority number wins. ----

match contains {
	"p": 10, "id": "AICP-001", "action": "block",
	"reason": "CUI/ITAR-marked content bound for an externally hosted AI service",
} if {
	cui_like
	external
}

match contains {
	"p": 20, "id": "AICP-002", "action": "block",
	"reason": "Credential or key material in AI-bound content",
} if {
	has_finding("SECRET")
}

match contains {
	"p": 30, "id": "AICP-005", "action": "block",
	"reason": "Forbidden tool",
} if {
	is_tool_call
	input.target.tool_name in forbidden_tools
}

match contains {
	"p": 40, "id": "AICP-003", "action": "route_local",
	"reason": "CUI-like content to a system not approved for CUI; route to on-prem model",
} if {
	cui_like
	not input.target.ai_system in cui_approved_systems
}

match contains {
	"p": 50, "id": "AICP-004", "action": "mask",
	"reason": "PII bound for external AI service; mask before transmission",
} if {
	has_finding("PII")
	external
}

match contains {
	"p": 55, "id": "AICP-007", "action": "mask",
	"reason": "CAGE code bound for external AI service",
} if {
	has_finding("CAGE_CODE")
	external
}

match contains {
	"p": 60, "id": "AICP-006", "action": "require_approval",
	"reason": "Tool call outside the auto-approved list requires human approval",
} if {
	is_tool_call
	not input.target.tool_name in auto_approved_tools
}

winner := m if {
	some m in match
	every other in match {
		m.p <= other.p
	}
}

default advisory := {
	"mode": "monitor",
	"action": "allow",
	"policy_id": "AICP-000",
	"policy_version": "dev",
	"reason": "No rule matched",
}

advisory := {
	"mode": "monitor",
	"action": winner.action,
	"policy_id": winner.id,
	"policy_version": policy_version,
	"reason": winner.reason,
}
