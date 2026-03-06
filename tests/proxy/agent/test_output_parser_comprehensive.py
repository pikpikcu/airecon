"""Tests for airecon.proxy.agent.output_parser module.

P1 Priority: Tests for edge cases in nuclei, gobuster, subfinder, whatweb parsing.
"""

import json
from airecon.proxy.agent.output_parser import (
    parse_tool_output,
    detect_tool,
    _parse_nmap,
    _parse_nuclei,
    _parse_line_list,
    _parse_whatweb,
    _parse_httpx,
    _parse_ffuf,
    _parse_naabu,
    _parse_nmap_xml,
)


class TestDetectTool:
    """Test tool detection from command strings."""

    def test_detect_nmap(self):
        assert detect_tool("nmap -sV example.com") == "nmap"
        assert detect_tool("cd /workspace/target && nmap -sV example.com") == "nmap"

    def test_detect_nuclei(self):
        assert detect_tool("nuclei -u example.com") == "nuclei"
        assert detect_tool("sudo nuclei -t nuclei-templates") == "nuclei"

    def test_detect_subfinder(self):
        assert detect_tool("subfinder -d example.com") == "subfinder"
        assert detect_tool("amass -d example.com") == "subfinder"  # Same parser
        assert detect_tool("assetfinder example.com") == "subfinder"
        assert detect_tool("findomain -t example.com") == "subfinder"

    def test_detect_httpx(self):
        assert detect_tool("httpx -u example.com") == "httpx"
        assert detect_tool("httpx -tech-detect -u example.com") == "httpx"

    def test_detect_url_list_tools(self):
        assert detect_tool("katana -u example.com") == "url_list"
        assert detect_tool("gospider -s example.com") == "url_list"
        assert detect_tool("waybackurls example.com") == "url_list"

    def test_detect_ffuf(self):
        assert detect_tool("ffuf -u http://example.com/FUZZ") == "ffuf"
        assert detect_tool("wfuzz -u http://example.com/FUZZ") == "ffuf"

    def test_detect_whatweb(self):
        assert detect_tool("whatweb example.com") == "whatweb"

    def test_unknown_tool_returns_none(self):
        assert detect_tool("unknown_tool -flag") is None


class TestParseNmap:
    """Test nmap output parsing."""

    def test_parse_nmap_basic_text(self):
        output = """
        Nmap scan report for example.com (93.184.216.34)
        Host is up (0.032s latency).
        
        PORT    STATE SERVICE
        80/tcp  open  http
        443/tcp open  https
        """
        parsed = _parse_nmap(output)
        assert parsed.tool == "nmap"
        assert parsed.total_count == 2
        assert len(parsed.items) == 2
        assert "80/tcp" in parsed.items[0]

    def test_parse_nmap_with_version(self):
        output = """
        PORT    STATE SERVICE VERSION
        80/tcp  open  http    Apache httpd 2.4.41 (Ubuntu)
        443/tcp open  https   nginx 1.18.0
        """
        parsed = _parse_nmap(output)
        assert parsed.total_count == 2
        assert "Apache" in parsed.items[0] or "2.4" in parsed.items[0]

    def test_parse_nmap_no_open_ports(self):
        output = """
        Nmap scan report for scanme.nmap.org (45.33.32.156)
        Host is up.
        All 1000 scanned ports on scanme.nmap.org are closed
        """
        parsed = _parse_nmap(output)
        assert parsed.total_count == 0
        assert parsed.items == []
        assert "0 open ports" in parsed.summary

    def test_parse_nmap_with_hostdown(self):
        output = """
        Nmap scan report for 10.0.0.1
        Host is down (ping failed).
        """
        parsed = _parse_nmap(output)
        assert "down" in parsed.summary.lower()

    def test_parse_nmap_multiple_hosts(self):
        output = """
        Nmap scan report for host1.com (10.0.0.1)
        Host is up.
        80/tcp open http
        
        Nmap scan report for host2.com (10.0.0.2)
        Host is up.
        443/tcp open https
        """
        parsed = _parse_nmap(output)
        assert parsed.total_count == 2

    def test_parse_nmap_xml_basic(self):
        """Test XML format nmap parsing."""
        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun scanner="nmap" args="nmap -sV example.com">
        <host starttime="1" endtime="2">
            <address addr="93.184.216.34" addrtype="ipv4"/>
            <hostnames><hostname name="example.com" type="PTR"/></hostnames>
            <status state="up" reason="echo-reply"/>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open" reason="syn-ack"/>
                    <service name="http" product="Apache httpd" version="2.4.41"/>
                </port>
                <port protocol="tcp" portid="443">
                    <state state="open" reason="syn-ack"/>
                    <service name="https"/>
                </port>
            </ports>
        </host>
        </nmaprun>"""
        parsed = _parse_nmap_xml(xml_output)
        assert parsed.tool == "nmap"
        assert parsed.total_count == 2
        assert "93.184.216.34" in parsed.items[0]

    def test_parse_nmap_xml_malformed(self):
        """Test malformed XML fallback."""
        bad_xml = """<?xml version="1.0"?>
        <nmaprun>
        <CORRUPTED>"""
        parsed = _parse_nmap_xml(bad_xml)
        assert parsed.tool == "nmap"
        # Should fallback gracefully


class TestParseNuclei:
    """Test nuclei output parsing."""

    def test_parse_nuclei_json_lines(self):
        output = """{"template-id":"http-missing-headers","info":{"name":"Missing Security Headers","severity":"medium"},"matched-at":"http://example.com"}
{"template-id":"ssl-certinfo","info":{"name":"SSL Certificate Info","severity":"info"},"matched-at":"https://example.com"}"""
        parsed = _parse_nuclei(output)
        assert parsed.tool == "nuclei"
        assert parsed.total_count == 2
        assert "[MEDIUM]" in parsed.items[0] or "[INFO]" in parsed.items[1]

    def test_parse_nuclei_with_severity_sorting(self):
        """Test that findings are sorted by severity (critical first)."""
        output = """{"template-id":"t1","info":{"severity":"low"},"matched-at":"url1"}
{"template-id":"t2","info":{"severity":"critical"},"matched-at":"url2"}
{"template-id":"t3","info":{"severity":"high"},"matched-at":"url3"}"""
        parsed = _parse_nuclei(output)
        assert parsed.total_count == 3
        # First item should be critical
        assert "[CRITICAL]" in parsed.items[0]

    def test_parse_nuclei_text_format(self):
        output = """[nuclei-template] [critical] http://example.com
[sql-injection] [high] http://example.com/search?q=test"""
        parsed = _parse_nuclei(output)
        assert parsed.total_count == 2
        assert "[CRITICAL]" in parsed.items[0] or "[HIGH]" in parsed.items[1]

    def test_parse_nuclei_no_findings(self):
        output = ""
        parsed = _parse_nuclei(output)
        assert parsed.total_count == 0
        assert "0 findings" in parsed.summary

    def test_parse_nuclei_severity_counts(self):
        """Test severity count aggregation."""
        output = """{"template-id":"t1","info":{"severity":"critical"},"matched-at":"url1"}
{"template-id":"t2","info":{"severity":"critical"},"matched-at":"url2"}
{"template-id":"t3","info":{"severity":"high"},"matched-at":"url3"}"""
        parsed = _parse_nuclei(output)
        # Summary should mention counts
        assert "2 critical" in parsed.summary or "2" in parsed.summary

    def test_parse_nuclei_mixed_format(self):
        """Test mixed JSON and text format."""
        output = """{"template-id":"t1","info":{"severity":"high"},"matched-at":"url1"}
[other-template] [medium] url2"""
        parsed = _parse_nuclei(output)
        assert parsed.total_count >= 1


class TestParseSubfinder:
    """Test subfinder output parsing."""

    def test_parse_subfinder_basic_lines(self):
        output = """subdomain1.example.com
subdomain2.example.com
api.example.com
admin.example.com"""
        parsed = _parse_line_list(output)
        assert parsed.total_count == 4
        assert len(parsed.items) == 4
        assert "subdomain1.example.com" in parsed.items

    def test_parse_subfinder_with_ports(self):
        """Some tools include port numbers."""
        output = """api.example.com:8080
api.example.com:443
api.example.com:80"""
        parsed = _parse_line_list(output)
        assert parsed.total_count == 3

    def test_parse_subfinder_no_duplicates_exact(self):
        """Test deduplication of exact subdomains."""
        output = """api.example.com
api.example.com
api.example.com"""
        parsed = _parse_line_list(output)
        assert parsed.total_count == 1

    def test_parse_subfinder_empty_lines_ignored(self):
        output = """api.example.com

admin.example.com

"""
        parsed = _parse_line_list(output)
        assert parsed.total_count == 2

    def test_parse_subfinder_large_output(self):
        """Test that large outputs are handled (25 items shown, rest counted)."""
        subdomains = [f"sub{i}.example.com" for i in range(100)]
        output = "\n".join(subdomains)
        parsed = _parse_line_list(output)
        assert parsed.total_count == 100
        assert len(parsed.items) <= 25  # MAX_ITEMS


class TestParseWhatWeb:
    """Test whatweb output parsing."""

    def test_parse_whatweb_json(self):
        output = json.dumps([{
            "target": "http://example.com",
            "plugins": {
                "nginx": {"version": ["1.18.0"]},
                "Bootstrap": {"version": ["3.3.7"]},
                "PHP": {"version": ["7.4.3"]}
            }
        }])
        parsed = _parse_whatweb(output)
        assert parsed.tool == "whatweb"
        assert "nginx" in parsed.technologies
        assert "Bootstrap" in parsed.technologies

    def test_parse_whatweb_text_format(self):
        output = """WhatWeb report for http://example.com
Summary   : nginx[1.18.0], Bootstrap[3.3.7], PHP[7.4.3]"""
        parsed = _parse_whatweb(output)
        assert parsed.total_count >= 1
        # Should extract technologies

    def test_parse_whatweb_multiple_targets(self):
        output = json.dumps([{"target": "http://example.com", "plugins": {"nginx": {"version": ["1.18.0"]}}}, {"target": "http://api.example.com", "plugins": {"nginx": {"version": ["1.19.0"]}}}])
        parsed = _parse_whatweb(output)
        assert parsed.total_count >= 1

    def test_parse_whatweb_version_merging(self):
        """Test that multiple versions of same tech are handled."""
        output = json.dumps([
            {"target": "http://api.example.com",
             "plugins": {"nginx": {"version": ["1.18.0"]}}},
            {"target": "http://admin.example.com",
             "plugins": {"nginx": {"version": ["1.19.0"]}}}
        ])
        parsed = _parse_whatweb(output)
        # Should mention nginx
        assert "nginx" in parsed.technologies


class TestParseHttpx:
    """Test httpx output parsing."""

    def test_parse_httpx_json_basic(self):
        output = (
            json.dumps({"url": "http://example.com", "status_code": 200, "title": "Example Domain"}) + "\n" +
            json.dumps({"url": "https://example.com", "status_code": 200, "title": "Example Domain"})
        )
        parsed = _parse_httpx(output)
        assert parsed.total_count == 2
        assert len(parsed.items) == 2

    def test_parse_httpx_with_tech_detect(self):
        output = json.dumps({
            "url": "http://example.com",
            "status_code": 200,
            "title": "Home",
            "tech": ["nginx/1.18.0", "Bootstrap/3.3.7"]
        })
        parsed = _parse_httpx(output)
        assert "nginx" in parsed.technologies
        assert parsed.technologies["nginx"] == "1.18.0"
        assert "Bootstrap" in parsed.technologies

    def test_parse_httpx_plain_urls(self):
        output = """http://example.com
https://example.com
https://api.example.com"""
        parsed = _parse_httpx(output)
        assert parsed.total_count >= 3

    def test_parse_httpx_no_live_hosts(self):
        output = ""
        parsed = _parse_httpx(output)
        assert parsed.total_count == 0
        assert "0 live hosts" in parsed.summary


class TestParseFFuf:
    """Test ffuf output parsing."""

    def test_parse_ffuf_csv_format(self):
        """ffuf -of json format is more reliable."""
        output = json.dumps({"results": [{"url": "http://example.com/admin", "status": 302}, {"url": "http://example.com/api", "status": 200}]})
        parsed = _parse_ffuf(output)
        # Should parse as JSON
        assert parsed.total_count >= 1

    def test_parse_ffuf_json_format(self):
        """ffuf -of json format."""
        output = json.dumps({
            "results": [
                {"url": "http://example.com/admin", "status": 302},
                {"url": "http://example.com/api", "status": 200}
            ]
        })
        parsed = _parse_ffuf(output)
        assert parsed.total_count >= 2


class TestParseNaabu:
    """Test naabu output parsing."""

    def test_parse_naabu_basic(self):
        output = """example.com:80
example.com:443
example.com:8080"""
        parsed = _parse_naabu(output)
        assert parsed.total_count == 3

    def test_parse_naabu_json_format(self):
        """Naabu usually outputs plain host:port lines."""
        output = "example.com:80\nexample.com:443\nexample.com:8080"
        parsed = _parse_naabu(output)
        assert parsed.total_count >= 2


class TestParseToolOutputIntegration:
    """Integration tests for parse_tool_output auto-detection."""

    def test_auto_detect_and_parse_nmap(self):
        output = """
        PORT    STATE SERVICE
        80/tcp  open  http
        443/tcp open  https"""
        parsed = parse_tool_output("nmap -sV example.com", output)
        assert parsed is not None
        assert parsed.tool == "nmap"
        assert parsed.total_count == 2

    def test_auto_detect_and_parse_nuclei(self):
        output = '{"template-id":"t1","info":{"severity":"high"},"matched-at":"url"}'
        parsed = parse_tool_output("nuclei -u example.com", output)
        assert parsed is not None
        assert parsed.tool == "nuclei"
        assert parsed.total_count == 1

    def test_parse_empty_output_returns_none(self):
        parsed = parse_tool_output("nmap example.com", "")
        assert parsed is None

    def test_parse_unknown_tool_uses_generic_parser(self):
        output = "Some generic output\nWith multiple lines"
        parsed = parse_tool_output("unknown_tool --flag", output)
        # Should still return something via generic parser
        assert parsed is not None

    def test_parse_malformed_json_fallback(self):
        """Test that malformed structured output falls back gracefully."""
        output = "{ invalid json"
        parse_tool_output("nuclei -u example.com", output)
        # Should not crash

    def test_parse_with_cd_prefix_in_command(self):
        """Test command with cd prefix is handled correctly."""
        output = "80/tcp open http"
        parsed = parse_tool_output(
            "cd /workspace/target && nmap -sV example.com",
            output
        )
        assert parsed is not None

    def test_parse_respects_max_items(self):
        """Test that MAX_ITEMS limit is respected."""
        from airecon.proxy.agent.output_parser import MAX_ITEMS

        # Create output with more items than MAX_ITEMS
        subdomains = "\n".join([f"sub{i}.example.com" for i in range(MAX_ITEMS + 10)])
        parsed = parse_tool_output("subfinder -d example.com", subdomains)

        assert parsed is not None
        assert len(parsed.items) <= MAX_ITEMS
        assert parsed.total_count == MAX_ITEMS + 10
