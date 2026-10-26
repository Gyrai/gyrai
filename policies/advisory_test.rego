package aicp_test

import rego.v1

import data.aicp

base := {
	"event_type": "ai.prompt.submitted",
	"target": {"ai_system": "openai.chatgpt", "hosting": "external_saas"},
	"content": {"dlp_findings": []},
}

test_clean_prompt_allowed if {
	aicp.advisory.action == "allow" with input as base
}

test_cui_to_external_blocked if {
	ev := object.union(base, {"content": {"dlp_findings": [{"category": "CUI_MARKING", "detector": "x", "count": 1}]}})
	aicp.advisory.action == "block" with input as ev
	aicp.advisory.policy_id == "AICP-001" with input as ev
}

test_cui_to_unapproved_internal_routes_local if {
	ev := object.union(base, {
		"target": {"ai_system": "internal.other", "hosting": "on_prem"},
		"content": {"dlp_findings": [{"category": "ITAR_TERM", "detector": "x", "count": 1}]},
	})
	aicp.advisory.action == "route_local" with input as ev
}

test_cui_to_approved_internal_allowed if {
	ev := object.union(base, {
		"target": {"ai_system": "m365.copilot", "hosting": "cloud_tenant"},
		"content": {"dlp_findings": [{"category": "CUI_MARKING", "detector": "x", "count": 1}]},
	})
	aicp.advisory.action == "allow" with input as ev
}

test_unlisted_tool_requires_approval if {
	ev := object.union(base, {"event_type": "ai.tool.called", "target": {"ai_system": "internal.ops-agent", "hosting": "on_prem", "tool_name": "send_email"}})
	aicp.advisory.action == "require_approval" with input as ev
}

test_secret_beats_cui_priority if {
	ev := object.union(base, {"content": {"dlp_findings": [
		{"category": "SECRET", "detector": "x", "count": 1},
		{"category": "PII", "detector": "x", "count": 1},
	]}})
	aicp.advisory.policy_id == "AICP-002" with input as ev
}
