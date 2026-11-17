import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FrontendSyntaxTests(unittest.TestCase):
    def test_embedded_javascript_parses(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is not installed")
        panel = (ROOT / "panel.py").read_text()
        html_match = re.search(r'INDEX_HTML = r"""(.*?)"""', panel, re.DOTALL)
        self.assertIsNotNone(html_match, "INDEX_HTML block not found")
        scripts = re.findall(r"<script(?:\\s[^>]*)?>(.*?)</script>",
                             html_match.group(1), re.DOTALL | re.IGNORECASE)
        self.assertTrue(scripts, "No inline JavaScript found")
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8") as fh:
            fh.write("\\n".join(scripts))
            fh.flush()
            result = subprocess.run([node, "--check", fh.name],
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
