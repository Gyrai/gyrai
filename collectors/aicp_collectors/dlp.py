"""Deterministic content scanner. Used by any collector that can see prompt text
(and later by the gateway's ingress stage). Returns schema-shaped dlp_findings.

Layer 1 of the DLP stack: regex on markings and well-known identifiers. Layers 2
(Presidio) and 3 (local classifier) plug in behind the same function signature.
Raw text never leaves this process; only categories and counts are emitted.
"""
import re

# category -> [(detector name, compiled pattern)]. To add a detector, append a pair to an
# existing category. A new category also needs adding to the schema's allowed list.
PATTERNS: dict[str, list[tuple[str, re.Pattern]]] = {
    "CUI_MARKING": [
        ("cui_banner", re.compile(r"\bCUI//(?:SP-)?[A-Z]{2,}(?:/[A-Z-]+)*", re.I)),
        ("cui_phrase", re.compile(r"\bCONTROLLED UNCLASSIFIED INFORMATION\b", re.I)),
        ("cui_basic", re.compile(r"\b(?:CUI|CTI)\s*(?:BASIC|SPECIFIED)\b", re.I)),
    ],
    "DISTRIBUTION_STATEMENT": [
        ("dist_stmt", re.compile(r"\bDISTRIBUTION STATEMENT [B-F]\b", re.I)),
        ("dist_phrase", re.compile(r"\bDistribution authorized to (?:U\.?S\.? Government|DoD)", re.I)),
    ],
    "ITAR_TERM": [
        ("itar", re.compile(r"\bITAR\b")),
        ("usml", re.compile(r"\bUSML\s+(?:Category|Cat\.?)\s+[IVX]+\b", re.I)),
        ("export_ctl", re.compile(r"\bexport[- ]controlled\b", re.I)),
        ("ear99", re.compile(r"\bEAR99\b|\bECCN\s*[0-9][A-E][0-9]{3}\b")),
    ],
    "CAGE_CODE": [
        ("cage", re.compile(r"\bCAGE(?:\s*code)?[:\s#]+[0-9A-Z]{5}\b", re.I)),
    ],
    "SECRET": [
        ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("bearer", re.compile(r"\b(?:api[_-]?key|token|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}", re.I)),
    ],
    "PII": [
        ("ssn", re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ],
}


def scan(text: str) -> list[dict]:
    """Look for every pattern in the text and return one finding per detector that matched:
    {"category", "detector", "count", "confidence"}. Findings hold counts only, never the matched text."""
    findings = []
    for category, detectors in PATTERNS.items():
        for name, rx in detectors:
            n = len(rx.findall(text or ""))
            if n:
                findings.append({"category": category, "detector": f"regex.{name}", "count": n, "confidence": 0.9})
    return findings


# ---- Reversible masking (gateway enforce mode) ----
#
# Replaces each detector match with a placeholder like [AICP:SECRET:2]. The vault
# maps placeholders back to originals so the response can be un-masked before it
# reaches the user. The vault lives only in memory for the life of one request.
#
# Note: masking a CUI *marking* removes the banner, not the controlled content.
# For CUI-marked prompts the default policy blocks or routes locally instead; mask
# is intended for identifiers (keys, SSNs, CAGE codes) inside otherwise-OK text.

# Categories safe to mask. Markings and ITAR terms are not here on purpose (see the note above).
MASKABLE = {"SECRET", "PII", "CAGE_CODE"}


def redact(text: str, categories: set[str] | None = None) -> tuple[str, dict[str, str]]:
    """Replace matches with numbered placeholders. Returns (masked text, vault), where the vault
    maps each placeholder back to the original so unredact() can restore it."""
    cats = categories or MASKABLE
    vault: dict[str, str] = {}
    out = text
    n = 0
    for category in cats:
        for _name, rx in PATTERNS.get(category, []):
            def _sub(m, _c=category):
                nonlocal n
                n += 1
                ph = f"[AICP:{_c}:{n}]"
                vault[ph] = m.group(0)
                return ph
            out = rx.sub(_sub, out)
    return out, vault


def unredact(text: str, vault: dict[str, str]) -> str:
    """Put the original values back wherever the model's reply repeats a placeholder."""
    for ph, original in vault.items():
        text = text.replace(ph, original)
    return text
