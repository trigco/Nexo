import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class InstallerSyncTests(unittest.TestCase):
    def assert_embedded_source_matches(self, filename, marker, command):
        installer = (ROOT / "install.sh").read_text()
        source = (ROOT / filename).read_text().strip()
        pattern = re.escape(command + marker + "'") + r"\n(.*?)\n" + re.escape(marker)
        match = re.search(pattern, installer, re.DOTALL)
        self.assertIsNotNone(match, f"Missing embedded {filename} heredoc")
        self.assertEqual(match.group(1).strip(), source,
                         f"install.sh has stale embedded {filename}")

    def test_panel_embedded_source_is_current(self):
        self.assert_embedded_source_matches(
            "panel.py", "PANEL_PY_EOF", "cat > /usr/local/bin/mpanel.py <<'"
        )

    def test_websocket_proxy_embedded_source_is_current(self):
        self.assert_embedded_source_matches(
            "wsproxy.py", "WSPROXY_PY_EOF", "cat > /usr/local/bin/wsproxy.py <<'"
        )


if __name__ == "__main__":
    unittest.main()
