import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.log_collector import LogParser, NginxLogParser


class NginxLogParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = NginxLogParser()

    def test_detects_sqli_with_plus_separated_payload(self):
        line = (
            '192.168.56.101 - - [21/Apr/2026:18:41:12 +0000] '
            '"GET /test.php?id=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" '
            '200 229 "-" "curl/8.17.0"'
        )

        event = self.parser.parse(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "nginx_sql_injection")
        self.assertIn("UNION SELECT", event.extra["normalized_path"].upper())

    def test_detects_percent_encoded_attack_payload(self):
        line = (
            '192.168.56.101 - - [21/Apr/2026:16:00:23 +0000] '
            '"GET /test.php?id=1%27%29%20ORDER%20BY%201--%20KxnM HTTP/1.1" '
            '200 248 "-" "sqlmap/1.9.11#stable (https://sqlmap.org)"'
        )

        event = self.parser.parse(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "nginx_sql_injection")
        self.assertIn("ORDER BY", event.extra["normalized_path"].upper())


class LogParserRoutingTests(unittest.TestCase):
    def test_apache_source_routes_to_web_parser(self):
        parser = LogParser()
        line = (
            '192.168.56.101 - - [21/Apr/2026:18:41:12 +0000] '
            '"GET /test.php?id=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" '
            '200 229 "-" "curl/8.17.0"'
        )

        event = parser.parse("apache", line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "nginx_sql_injection")

    def test_detects_scanner_user_agent_on_non_malicious_path(self):
        parser = NginxLogParser()
        line = (
            '203.0.113.5 - - [21/Apr/2026:18:41:12 +0000] '
            '"GET /login HTTP/1.1" 200 229 "-" "sqlmap/1.9.11#stable (https://sqlmap.org)"'
        )

        event = parser.parse(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "nginx_scanner_ua")


if __name__ == "__main__":
    unittest.main()
