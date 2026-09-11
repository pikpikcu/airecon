"""Tests for Phase 3 improvements:
- sqlmap/nikto/dalfox/wpscan parsers
- tested_injection_points / suggested_correlations tracking
- session_to_context untested injection points
- auto_load_skills_for_technologies
- correlation dedup
"""

from __future__ import annotations

from airecon.proxy.agent.output_parser import parse_tool_output
from airecon.proxy.agent.session import (
    SessionData,
    _extract_injection_points,
    _load_redirect_path_indicators,
    get_untested_injection_points,
    injection_point_key,
    mark_injection_point_tested,
    session_to_context,
)
from airecon.proxy.correlation import _corr_fingerprint, run_correlation
from airecon.proxy.system import auto_load_skills_for_technologies


# ── sqlmap parser ─────────────────────────────────────────────────────────────

SQLMAP_OUTPUT_VULN = """\
[11:00:00] [INFO] testing connection to the target URL
URL: http://example.com/search?q=test
[11:00:01] [INFO] GET parameter 'q' is vulnerable. Do you want to keep testing others? [y/N]
Parameter 'q' is vulnerable to SQL injection
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=test' AND 1=1-- -
back-end DBMS is MySQL >= 5.0
"""

SQLMAP_OUTPUT_CLEAN = """\
[11:00:00] [INFO] testing connection to the target URL
[11:00:05] [WARNING] GET parameter 'q' does not appear to be injectable
[11:00:05] [CRITICAL] no parameter(s) found
"""


def test_sqlmap_vuln_detected():
    result = parse_tool_output(
        "sqlmap -u 'http://example.com/search?q=test'", SQLMAP_OUTPUT_VULN
    )
    assert result is not None
    assert result.tool == "sqlmap"
    assert result.total_count > 0
    assert any(
        "vuln" in item.lower() or "sqli" in item.lower() or "q" in item.lower()
        for item in result.items
    )
    assert "mysql" in result.summary.lower() or result.total_count > 0


def test_sqlmap_clean_returns_zero():
    result = parse_tool_output("sqlmap -u 'http://example.com/'", SQLMAP_OUTPUT_CLEAN)
    assert result is not None
    assert result.total_count == 0


# ── nikto parser ─────────────────────────────────────────────────────────────

NIKTO_OUTPUT = """\
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.1
+ Target Hostname:    example.com
+ Target Port:        80
---------------------------------------------------------------------------
+ Server: Apache/2.4.49
+ The anti-clickjacking X-Frame-Options header is not present.
+ OSVDB-3268: /backup/: Directory indexing found.
+ /server-status: Apache server-status is accessible - consider granting access to localhost only.
+ OSVDB-3092: /admin/: This might be interesting...
+ XSS test: /search?q=<script>alert(1)</script> could be vulnerable to XSS.
---------------------------------------------------------------------------
"""


def test_nikto_findings_parsed():
    result = parse_tool_output("nikto -h http://example.com", NIKTO_OUTPUT)
    assert result is not None
    assert result.tool == "nikto"
    assert result.total_count >= 3
    # XSS finding should be HIGH
    high_findings = [f for f in result.items if "[HIGH]" in f]
    assert len(high_findings) >= 1


def test_nikto_no_findings_returns_zero():
    result = parse_tool_output(
        "nikto -h http://example.com", "- Nikto v2.1.6\n- 0 items found.\n"
    )
    assert result is not None
    assert result.total_count == 0


# ── dalfox parser ─────────────────────────────────────────────────────────────

DALFOX_OUTPUT = """\
[*] HAHWUL Dalfox
[*] Starting analysis...
[V] Reflected XSS found at http://example.com/search?q=<script>alert(1)</script>
[POC] http://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
[G] Potential XSS found at http://example.com/filter?cat=test
"""


def test_dalfox_xss_parsed():
    result = parse_tool_output(
        "dalfox url http://example.com/search?q=test", DALFOX_OUTPUT
    )
    assert result is not None
    assert result.tool == "dalfox"
    assert result.total_count >= 2
    verified = [i for i in result.items if "VERIFIED" in i or "[HIGH]" in i]
    assert len(verified) >= 1


def test_dalfox_no_xss():
    result = parse_tool_output(
        "dalfox url http://clean.com/", "[*] Dalfox\n[*] Scan complete. No XSS.\n"
    )
    assert result is not None
    assert result.total_count == 0


# ── wpscan parser ─────────────────────────────────────────────────────────────

WPSCAN_OUTPUT = """\
[+] WordPress version 5.8.1 identified
[!] 3 vulnerabilities identified from WPScan DB
[!] WordPress 5.8.1 - Authenticated XSS via Post Slugs (CVE-2021-39200)
[!] WordPress 5.8.1 - SQL Injection (CVE-2021-39201)
[+] Username found: admin (ID: 1)
[i] Plugin: contact-form-7 2.3 found
"""


def test_wpscan_vulns_parsed():
    result = parse_tool_output("wpscan --url http://wp.example.com", WPSCAN_OUTPUT)
    assert result is not None
    assert result.tool == "wpscan"
    assert result.total_count >= 2
    high_vulns = [i for i in result.items if "[HIGH]" in i or "[CRITICAL]" in i]
    assert len(high_vulns) >= 1


# ── tested_injection_points ───────────────────────────────────────────────────


def test_mark_and_get_untested():
    session = SessionData(target="example.com", session_id="test_123")
    session.injection_points = [
        {
            "url": "http://example.com/",
            "parameter": "id",
            "method": "GET",
            "type_hint": "IDOR",
        },
        {
            "url": "http://example.com/",
            "parameter": "q",
            "method": "GET",
            "type_hint": "INJECT",
        },
        {
            "url": "http://example.com/api",
            "parameter": "token",
            "method": "POST",
            "type_hint": "AUTH",
        },
    ]

    # Initially all untested
    untested = get_untested_injection_points(session)
    assert len(untested) == 3

    # Mark one as tested
    mark_injection_point_tested(session, "http://example.com/", "id", "GET")
    untested = get_untested_injection_points(session)
    assert len(untested) == 2
    params = [pt["parameter"] for pt in untested]
    assert "id" not in params
    assert "q" in params


def test_mark_tested_no_duplicate():
    session = SessionData(target="example.com", session_id="test_456")
    mark_injection_point_tested(session, "http://example.com/", "id")
    mark_injection_point_tested(session, "http://example.com/", "id")  # duplicate
    assert len(session.tested_injection_points) == 1


def test_injection_point_key_format():
    # Trailing slash is stripped during normalization.
    key = injection_point_key("http://example.com/", "id", "GET")
    assert key == "http://example.com||id||GET"


def test_injection_point_key_normalizes_trailing_slash():
    # /api/ and /api must produce the same dedup key.
    key_with_slash = injection_point_key("http://example.com/api/", "id", "GET")
    key_no_slash = injection_point_key("http://example.com/api", "id", "GET")
    assert key_with_slash == key_no_slash


def test_injection_point_key_normalizes_case():
    key_upper = injection_point_key("HTTP://EXAMPLE.COM/api", "id", "GET")
    key_lower = injection_point_key("http://example.com/api", "id", "GET")
    assert key_upper == key_lower


# ── session_to_context shows untested ────────────────────────────────────────


def test_session_context_shows_untested():
    session = SessionData(target="example.com", session_id="ctx_test")
    session.injection_points = [
        {
            "url": "http://example.com/",
            "parameter": "id",
            "method": "GET",
            "type_hint": "IDOR",
        },
        {
            "url": "http://example.com/",
            "parameter": "q",
            "method": "GET",
            "type_hint": "INJECT",
        },
    ]
    # One tested, one not
    mark_injection_point_tested(session, "http://example.com/", "id", "GET")
    session.scan_count = 1

    ctx = session_to_context(session)
    assert "UNTESTED" in ctx or "untested" in ctx
    assert "q" in ctx  # untested param shows in context


def test_session_context_all_tested():
    session = SessionData(target="example.com", session_id="ctx_test2")
    session.injection_points = [
        {
            "url": "http://example.com/",
            "parameter": "id",
            "method": "GET",
            "type_hint": "IDOR",
        },
    ]
    mark_injection_point_tested(session, "http://example.com/", "id", "GET")
    session.scan_count = 1
    ctx = session_to_context(session)
    assert "tested" in ctx.lower()


# ── auto_load_skills_for_technologies ─────────────────────────────────────────


def test_tech_skill_loads_wordpress():
    ctx, names = auto_load_skills_for_technologies({"WordPress": "5.8.1"})
    assert ctx != ""
    assert len(names) > 0
    assert all("/" in n for n in names)


def test_tech_skill_loads_nginx():
    ctx, names = auto_load_skills_for_technologies({"nginx": "1.18.0"})
    assert ctx != ""


def test_tech_skill_dedup_already_loaded():
    already = set()
    ctx1, names1 = auto_load_skills_for_technologies(
        {"WordPress": "5.8"}, already_loaded=already
    )
    # Second call with same already_loaded set should skip
    ctx2, names2 = auto_load_skills_for_technologies(
        {"WordPress": "5.8"}, already_loaded=already
    )
    assert ctx1 != ""
    assert ctx2 == ""  # already loaded
    assert names2 == []


def test_tech_skill_empty_technologies():
    ctx, names = auto_load_skills_for_technologies({})
    assert ctx == ""
    assert names == []


# ── correlation dedup ─────────────────────────────────────────────────────────


def test_corr_fingerprint_port():
    corr = {"type": "port", "port": 80}
    assert _corr_fingerprint(corr) == "port:80"


def test_corr_fingerprint_tech():
    corr = {"type": "technology", "technology": "wordpress"}
    assert _corr_fingerprint(corr) == "tech:wordpress"


def test_correlation_dedup_removes_already_suggested():
    session = SessionData(target="example.com", session_id="dedup_test")
    session.technologies = {"nginx": "1.18.0"}
    session.open_ports = {"example.com": [80, 443]}

    # First call — get all results
    results1 = run_correlation(session)
    assert len(results1) > 0

    # Second call — should be empty (all suggestions already seen)
    results2 = run_correlation(session)
    # PORT 80 and nginx were already suggested — shouldn't be in results2
    port_80_in_r2 = any(
        r.get("type") == "port" and r.get("port") == 80 for r in results2
    )
    # At minimum the already-suggested ones should be filtered
    assert len(results2) <= len(results1)
    # After second call, no port:80 should appear (already seen)
    assert not port_80_in_r2


def test_correlation_suggested_correlations_persisted():
    session = SessionData(target="example.com", session_id="persist_test")
    session.technologies = {"django": "3.2"}
    session.open_ports = {"example.com": [443]}

    run_correlation(session)
    assert len(session.suggested_correlations) > 0


# ── path-context reclassification (SSRF → OPEN_REDIRECT) ────────────────────


def test_load_redirect_path_indicators_returns_nonempty():
    """_load_redirect_path_indicators() must return indicators from patterns.json."""
    indicators = _load_redirect_path_indicators()
    assert isinstance(indicators, frozenset)
    assert len(indicators) > 0
    # "aredirurl" is in patterns.json open_redirect_url_param.indicators
    assert "aredirurl" in indicators


def test_extract_injection_points_ssrf_reclassified_to_open_redirect():
    """?url= on /api/frontendweb.aredirurl → OPEN_REDIRECT, not SSRF.

    This is the real-world bug: LLM tested cloud metadata IPs instead of
    javascript: protocol because the param was typed as SSRF.
    """
    pts = _extract_injection_points(
        "https://myaccount.genexus.com/api/frontendweb.aredirurl?url=javascript:alert(1)"
    )
    assert len(pts) == 1
    assert pts[0]["parameter"] == "url"
    assert pts[0]["type_hint"] == "OPEN_REDIRECT"


def test_extract_injection_points_ssrf_stays_ssrf_on_non_redirect_path():
    """?url= on /fetch (no redirect indicator) must stay SSRF."""
    pts = _extract_injection_points("https://example.com/fetch?url=http://internal/")
    assert len(pts) == 1
    assert pts[0]["parameter"] == "url"
    assert pts[0]["type_hint"] == "SSRF"


def test_extract_injection_points_uri_reclassified_on_forward_path():
    """?uri= on /forward (path contains 'forward' indicator) → OPEN_REDIRECT.
    'uri' maps to SSRF in PARAM_TYPE_MAP; the path context triggers reclassification.
    """
    pts = _extract_injection_points(
        "https://example.com/forward?uri=http://attacker.com/"
    )
    url_type_params = [p for p in pts if p["parameter"] == "uri"]
    assert url_type_params, "Expected 'uri' param in injection points"
    assert url_type_params[0]["type_hint"] == "OPEN_REDIRECT"


def test_extract_injection_points_ssrf_unaffected_when_no_path_indicator():
    """?uri= on /api/webhook (no redirect indicator) stays SSRF."""
    pts = _extract_injection_points(
        "https://example.com/api/webhook?uri=http://internal/"
    )
    cb = [p for p in pts if p["parameter"] == "uri"]
    assert cb, "Expected 'uri' param"
    # uri maps to SSRF in PARAM_TYPE_MAP — /api/webhook has no redirect indicator
    assert cb[0]["type_hint"] == "SSRF"


def test_extract_injection_points_multiple_params_reclassified_selectively():
    """On a redirect path, only SSRF-typed params are reclassified.
    Other types (INJECT, IDOR) stay unchanged.
    """
    pts = _extract_injection_points(
        "https://example.com/goto?url=http://x.com&id=42&q=search"
    )
    by_param = {p["parameter"]: p["type_hint"] for p in pts}
    # "url" → SSRF in map, path has "goto" → OPEN_REDIRECT
    assert by_param.get("url") == "OPEN_REDIRECT"
    # "id" → IDOR (numeric value heuristic or _PARAM_TYPE_MAP), no reclassification
    assert by_param.get("id") in ("IDOR", "INJECT")
    # "q" → non-SSRF type (SQLi_XSS or INJECT), no reclassification
    assert by_param.get("q") != "SSRF"
    assert by_param.get("q") != "OPEN_REDIRECT"
