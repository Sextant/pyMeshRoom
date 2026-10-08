import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ManualScriptTests(unittest.TestCase):
    def test_manual_scripts_have_expected_safety_guards(self):
        start = (ROOT / "scripts" / "start-pymeshroom.sh").read_text(encoding="utf-8")
        stop = (ROOT / "scripts" / "stop-pymeshroom.sh").read_text(encoding="utf-8")
        self.assertIn('"$ROOT/.venv/bin/python"', start)
        self.assertIn("systemctl is-active --quiet meshroom.service", start)
        self.assertIn("--config", start)
        self.assertIn("meshroom.pid", start)
        self.assertNotIn("KILL", stop)
        self.assertIn('"/proc/$PID/cmdline"', stop)


if __name__ == "__main__":
    unittest.main()
