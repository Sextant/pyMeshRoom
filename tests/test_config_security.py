import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ConfigSecurityTests(unittest.TestCase):
    def test_example_has_no_default_credentials(self):
        config = json.loads((ROOT / "meshroom" / "meshroom.json.example").read_text(encoding="utf-8"))
        self.assertEqual(config["access"]["admin_password"], "")
        self.assertEqual(config["access"]["room_password"], "")
        self.assertEqual(config["dashboard"]["web_password"], "")
        self.assertEqual(config["mqtt"]["mqtt_username"], "")
        self.assertEqual(config["mqtt"]["mqtt_password"], "")


if __name__ == "__main__":
    unittest.main()
