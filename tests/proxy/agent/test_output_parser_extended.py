"""Extended tests for output_parser.py covering nuclei, whatweb, nmap XML,
naabu, subfinder, and edge cases not covered by the base test file."""

import json
import pytest
from airecon.proxy.agent.output_parser import (
    parse_tool_output,
    detect_tool,
    ParsedOutput,
)


# ── detect_tool edge cases ────────────────────────────────────────────────────

class TestDetectToolEdgeCases:
    def test_detect_with_cd_prefix(self):
        cmd = "cd /workspace/session_abc && nmap -sV 10.0.0.1"
        assert detect_tool(cmd) == "nmap"

    def test_detect_sudo_prefix(self):
        assert detect_tool("sudo nmap -sS 10.0.0.1") == "nmap"

    def test_detect_subfinder(self):
        assert detect_tool("subfinder -d example.com -silent") == "subfinder"

    def test_detect_amass_maps_to_subfinder(self):
        assert detect_tool("amass enum -d example.com") == "subfinder"

    def test_detect_assetfinder_maps_to_subfinder(self):
        assert detect_tool("assetfinder --subs-only example.com") == "subfinder"

    def test_detect_naabu(self):
        assert detect_tool("naabu -host 10.0.0.1 -p 80,443") == "naabu"

    def test_detect_whatweb(self):
        assert detect_tool("whatweb -a 3 http://example.com") == "whatweb"

    def test_detect_nuclei(self):
        assert detect_tool("nuclei -t cves/ -u http://example.com") == "nuclei"

    def test_detect_gospider_maps_to_url_list(self):
        assert detect_tool("gospider -s http://example.com") == "url_list"

    def test_detect_waybackurls_maps_to_url_list(self):
        assert detect_tool("waybackurls example.com") == "url_list"

    def test_detect_dirsearch_maps_to_url_list(self):
        assert detect_tool("dirsearch -u http://example.com -w wordlist.txt") == "url_list"

    def test_detect_unknown_returns_none(self):
        assert detect_tool("joomscan -u http://example.com") is None

    def test_detect_empty_command(self):
        assert detect_tool("") is None


# ── Nuclei output parsing ─────────────────────────────────────────────────────

class TestNucleiParser:
    def test_nuclei_json_lines_basic(self):
        line = json.dumps({
            "template-id": "cve-2021-44228",
            "info": {"name": "Log4Shell", "severity": "critical"},
            "matched-at": "http://example.com/api"
        })
        parsed = parse_tool_output("nuclei -t cves/", line)
        assert parsed is not None
        assert parsed.tool == "nuclei"
        assert parsed.total_count == 1
        assert "CRITICAL" in parsed.items[0]
        assert "Log4Shell" in parsed.items[0]

    def test_nuclei_multiple_severities_sorted(self):
        lines = [
            json.dumps({"template-id": "info-t", "info": {"name": "Info Finding", "severity": "info"}, "matched-at": "http://x.com"}),
            json.dumps({"template-id": "crit-t", "info": {"name": "Critical Bug", "severity": "critical"}, "matched-at": "http://x.com"}),
            json.dumps({"template-id": "high-t", "info": {"name": "High Risk", "severity": "high"}, "matched-at": "http://x.com"}),
        ]
        parsed = parse_tool_output("nuclei -t all/", "\n".join(lines))
        assert parsed is not None
        assert parsed.total_count == 3
        # Critical should be first
        assert "CRITICAL" in parsed.items[0]
        assert "HIGH" in parsed.items[1]

    def test_nuclei_text_format(self):
        stdout = (
            "[cve-2019-11043] [critical] [http] http://example.com/php-fpm\n"
            "[open-redirect] [medium] [http] http://example.com/redirect?url=evil\n"
        )
        parsed = parse_tool_output("nuclei", stdout)
        assert parsed is not None
        assert parsed.total_count == 2
        assert "CRITICAL" in parsed.items[0] or "MEDIUM" in parsed.items[0]

    def test_nuclei_zero_findings(self):
        stdout = "\n\n  \n"
        parsed = parse_tool_output("nuclei -u http://example.com", stdout)
        # Returns None for fully empty output
        assert parsed is None

    def test_nuclei_summary_contains_severity_counts(self):
        lines = "\n".join([
            json.dumps({"template-id": "t1", "info": {"name": "A", "severity": "high"}, "matched-at": "http://x"}),
            json.dumps({"template-id": "t2", "info": {"name": "B", "severity": "high"}, "matched-at": "http://x"}),
            json.dumps({"template-id": "t3", "info": {"name": "C", "severity": "low"}, "matched-at": "http://x"}),
        ])
        parsed = parse_tool_output("nuclei -t exposures/", lines)
        assert parsed is not None
        assert "high" in parsed.summary.lower() or "2" in parsed.summary


# ── WhatWeb output parsing ────────────────────────────────────────────────────

class TestWhatWebParser:
    def test_whatweb_json_format(self):
        data = json.dumps([{
            "target": "http://example.com",
            "plugins": {
                "nginx": {"version": ["1.18.0"]},
                "PHP": {"version": ["8.1.0"]},
                "Bootstrap": {"version": ["4.6.0"]},
            }
        }])
        parsed = parse_tool_output("whatweb -a 3 http://example.com", data)
        assert parsed is not None
        assert parsed.tool == "whatweb"
        assert parsed.technologies.get("nginx") == "1.18.0"
        assert parsed.technologies.get("PHP") == "8.1.0"
        assert parsed.total_count == 3

    def test_whatweb_json_plugin_no_version(self):
        data = json.dumps([{
            "target": "http://example.com",
            "plugins": {"React": {}, "webpack": {}}
        }])
        parsed = parse_tool_output("whatweb http://example.com", data)
        assert parsed is not None
        assert "React" in parsed.technologies
        assert parsed.technologies["React"] == ""

    def test_whatweb_text_format(self):
        stdout = (
            "WhatWeb report for http://example.com\n"
            "Summary   : nginx[1.18.0], PHP[7.4.33], Bootstrap[3.3.7], Email[admin@example.com]\n"
        )
        parsed = parse_tool_output("whatweb http://example.com", stdout)
        assert parsed is not None
        assert parsed.technologies.get("nginx") == "1.18.0"
        assert parsed.technologies.get("PHP") == "7.4.33"
        # Email should be skipped (it's in _SKIP set)
        assert "Email" not in parsed.technologies

    def test_whatweb_text_no_version_bare_names(self):
        stdout = (
            "WhatWeb report for http://example.com\n"
            "Summary   : Apache, WordPress\n"
        )
        parsed = parse_tool_output("whatweb http://example.com", stdout)
        assert parsed is not None
        # Bare capitalised names should be captured
        assert "Apache" in parsed.technologies or "WordPress" in parsed.technologies

    def test_whatweb_no_tech_found(self):
        stdout = "WhatWeb report for http://example.com\n"
        parsed = parse_tool_output("whatweb http://example.com", stdout)
        assert parsed is not None
        assert parsed.total_count == 0


# ── Nmap XML parsing ──────────────────────────────────────────────────────────

class TestNmapXMLParser:
    def _xml_output(self, ports):
        """Build minimal nmap XML with given port specs."""
        port_els = ""
        for portid, proto, state, service, product, version in ports:
            port_els += (
                f'<port protocol="{proto}" portid="{portid}">'
                f'<state state="{state}"/>'
                f'<service name="{service}" product="{product}" version="{version}"/>'
                f'</port>'
            )
        return (
            '<?xml version="1.0"?>'
            '<nmaprun>'
            '<host><status state="up"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            f'<ports>{port_els}</ports>'
            '</host>'
            '</nmaprun>'
        )

    def test_nmap_xml_open_ports(self):
        xml = self._xml_output([
            ("80", "tcp", "open", "http", "Apache", "2.4.51"),
            ("443", "tcp", "open", "https", "nginx", "1.18.0"),
        ])
        parsed = parse_tool_output("nmap -sV -oX -", xml)
        assert parsed is not None
        assert parsed.tool == "nmap"
        assert parsed.total_count == 2
        assert any("80" in item for item in parsed.items)

    def test_nmap_xml_filtered_ports_included(self):
        xml = self._xml_output([
            ("22", "tcp", "filtered", "ssh", "", ""),
        ])
        parsed = parse_tool_output("nmap -sS", xml)
        assert parsed is not None
        assert parsed.total_count == 1

    def test_nmap_xml_closed_ports_excluded(self):
        xml = self._xml_output([
            ("8080", "tcp", "closed", "http-proxy", "", ""),
        ])
        parsed = parse_tool_output("nmap -p 8080", xml)
        assert parsed is not None
        assert parsed.total_count == 0

    def test_nmap_xml_malformed_fallback_to_text(self):
        bad_xml = "<?xml version='1.0'?><nmaprun><UNCLOSED"
        parsed = parse_tool_output("nmap -oX -", bad_xml)
        # Should not raise — falls back to text or raw
        assert parsed is not None

    def test_nmap_text_no_open_ports(self):
        stdout = "Starting Nmap 7.94\nAll 1000 scanned ports are closed\n"
        parsed = parse_tool_output("nmap 10.0.0.1", stdout)
        assert parsed is not None
        assert parsed.total_count == 0
        assert "0 open" in parsed.summary


# ── Naabu parsing ─────────────────────────────────────────────────────────────

class TestNaabuParser:
    def test_naabu_host_port_lines(self):
        stdout = "10.0.0.1:80\n10.0.0.1:443\n10.0.0.2:22\n"
        parsed = parse_tool_output("naabu -host 10.0.0.0/24", stdout)
        assert parsed is not None
        assert parsed.tool == "naabu"
        assert parsed.total_count == 3

    def test_naabu_counts_all_lines(self):
        # naabu parser counts all lines as reported (no dedup — each line is
        # a separate port discovery event even if the same port appears twice)
        stdout = "10.0.0.1:80\n10.0.0.1:80\n10.0.0.1:443\n"
        parsed = parse_tool_output("naabu -iL hosts.txt", stdout)
        assert parsed is not None
        assert parsed.total_count == 3


# ── Subfinder / line-list parsing ────────────────────────────────────────────

class TestSubfinderParser:
    def test_subfinder_basic(self):
        stdout = "api.example.com\ndev.example.com\nstaging.example.com\n"
        parsed = parse_tool_output("subfinder -d example.com", stdout)
        assert parsed is not None
        assert parsed.tool == "subfinder"
        assert parsed.total_count == 3

    def test_subfinder_deduplicates(self):
        stdout = "api.example.com\napi.example.com\ndev.example.com\n"
        parsed = parse_tool_output("subfinder -d example.com", stdout)
        assert parsed is not None
        assert parsed.total_count == 2

    def test_subfinder_skips_comment_lines(self):
        stdout = "// This is a comment\napi.example.com\n"
        parsed = parse_tool_output("subfinder -d example.com", stdout)
        assert parsed is not None
        assert parsed.total_count == 1

    def test_amass_same_parser(self):
        stdout = "sub1.target.com\nsub2.target.com\n"
        parsed = parse_tool_output("amass enum -d target.com", stdout)
        assert parsed is not None
        assert parsed.total_count == 2


# ── Generic smart parser fallback ────────────────────────────────────────────

class TestGenericSmartParserExtended:
    def test_unknown_tool_gets_tool_name_from_command(self):
        stdout = "[*] Found: victim1.com\n[*] Found: victim2.com\n"
        parsed = parse_tool_output("theHarvester -d example.com", stdout)
        assert parsed is not None
        assert parsed.tool == "theHarvester"

    def test_json_lines_detected_auto(self):
        lines = "\n".join([
            json.dumps({"host": f"sub{i}.example.com", "ip": f"1.1.1.{i}"})
            for i in range(5)
        ])
        parsed = parse_tool_output("customtool -d example.com", lines)
        assert parsed is not None
        assert parsed.total_count == 5

    def test_url_list_auto_detected(self):
        stdout = (
            "http://example.com/api/v1\n"
            "http://example.com/admin\n"
            "http://example.com/login\n"
        )
        parsed = parse_tool_output("gospider -s http://example.com", stdout)
        assert parsed is not None
        assert parsed.total_count == 3

    def test_truly_unknown_tool_still_returns_output(self):
        stdout = "Some unstructured output\nwith multiple lines\nand no pattern"
        parsed = parse_tool_output("somerandombinary -v", stdout)
        assert parsed is not None
        assert parsed.total_count > 0
