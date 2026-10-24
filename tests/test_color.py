"""Rich is presentation only: JSON and redirected output stay unchanged."""
import contextlib
import io
import json
import os
import re
import unittest
from unittest.mock import patch

from netwatch.cli import display
import test_arch_output


class Terminal(io.StringIO):
    def isatty(self):
        return True


class ColorTests(unittest.TestCase):
    def render(self, result, *, tty=True, env=None, **kwargs):
        out = Terminal() if tty else io.StringIO()
        settings = {"TERM": "xterm-256color", "COLUMNS": "120"}
        settings.update(env or {})
        with patch.dict(os.environ, settings, clear=True), contextlib.redirect_stdout(out):
            display(result, **kwargs)
        return out.getvalue()

    def test_tty_styled_but_pipes_and_no_color_are_plain(self):
        result = test_arch_output.OutputTests().result()
        styled = self.render(result)
        self.assertIn("\x1b[", styled)
        self.assertIn("Needs review", styled)
        plain = self.render(result, tty=False)
        self.assertNotIn("\x1b", plain)
        for env in ({"NO_COLOR": "1"}, {"NO_COLOR": ""}, {"TERM": "dumb"}):
            self.assertEqual(self.render(result, env=env), plain)
        self.assertEqual(self.render(result, tty=False, env={"FORCE_COLOR": "1"}), plain)

    def test_json_is_exact_even_on_color_terminal(self):
        result = test_arch_output.OutputTests().result()
        output = self.render(result, json_output=True)
        self.assertEqual(json.loads(output), result)
        self.assertEqual(output, self.render(result, tty=False, json_output=True))
        self.assertNotIn("\x1b", output)

    def test_markup_and_control_characters_are_literal(self):
        result = test_arch_output.OutputTests().result()
        result[0]["report"]["warnings"] = ["[bold red]payload[/bold red]\x1b[31m\nnext"]
        output = self.render(result)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
        self.assertIn("[bold red]payload[/bold red]", plain)
        self.assertIn(r"\u001b[31m\nnext", plain)
        self.assertNotIn("\x1b", plain)

    def test_update_labels_do_not_equate_candidates_with_security_fixes(self):
        result = test_arch_output.OutputTests().result()
        report = result[0]["report"]
        report["findings"] = [report["findings"][0], {**report["findings"][1], "package": "affected", "state": "affected"}]
        report["findings"][0]["severity"] = "Critical"
        report["updates"] = [{"package": n, "candidate": "10"} for n in ("ordinary", "example", "affected")]
        output = self.render(result, tty=False)
        self.assertIn("[affected]", output)
        self.assertIn("[review]", output)
        self.assertIn("reported severity: Critical", output)
        self.assertIn("not all are security fixes", output)
        updates = output.split("Available updates:")[1]
        self.assertLess(updates.index("affected:"), updates.index("example:"))
        self.assertLess(updates.index("example:"), updates.index("ordinary:"))
        styled = self.render(result)
        review_line = next(line for line in styled.splitlines() if "[review]" in line)
        self.assertIn("\x1b[33m", review_line)
        self.assertNotIn("\x1b[31m", review_line)

    def test_wide_terminal_uses_tables_and_compact_summary(self):
        result = test_arch_output.OutputTests().result()
        report = result[0]["report"]
        report["findings"][0]["severity"] = "Critical"
        output = self.render(result)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
        self.assertIn("╭", plain)
        self.assertIn("0 affected", plain)
        self.assertNotIn("Affected: 0 packages", plain)
        self.assertIn("Reported severity", plain)
        self.assertIn("CRITICAL", plain)
        self.assertIn("Installed", plain)
        self.assertIn("Available", plain)
        self.assertNotIn("Reported fixes: none listed", plain)
        self.assertEqual(plain.count("No published fix versions"), 1)
        self.assertIn("Showing 10 of 50 updates", plain)
        self.assertIn("\x1b[1;37;41m", output)
        full = re.sub(r"\x1b\[[0-9;]*m", "", self.render(result, show_all=True))
        self.assertIn("pkg-49", full)
        self.assertIn("AVG-199", full)
        self.assertNotIn("Showing 10", full)

    def test_narrow_terminal_and_generic_results_render(self):
        result = test_arch_output.OutputTests().result()
        output = self.render(result, env={"COLUMNS": "40"})
        self.assertIn("Needs review", output)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", output)
        self.assertTrue(all(len(line) <= 40 for line in plain.splitlines()))
        self.assertIn("\x1b[", self.render({"status": "proposed", "id": 1}))
        self.assertNotIn("\x1b", self.render({"status": "proposed", "id": 1}, tty=False))


if __name__ == "__main__":
    unittest.main()
