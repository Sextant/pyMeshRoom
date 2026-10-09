import pathlib
import sys
import tempfile
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "meshroom"))
from meshroom import ICON_NAMES, PACKAGED_ICONS_DIR, dashboard_icon_file


class DashboardIconTests(unittest.TestCase):
    def test_packaged_icons_are_the_default_for_a_new_install(self):
        with tempfile.TemporaryDirectory() as data_dir:
            for name in ICON_NAMES:
                self.assertEqual(
                    dashboard_icon_file(data_dir, name),
                    str(pathlib.Path(PACKAGED_ICONS_DIR) / f"{name}.png"),
                )

    def test_private_data_directory_can_override_a_packaged_icon(self):
        with tempfile.TemporaryDirectory() as data_dir:
            icon_dir = pathlib.Path(data_dir) / "icons"
            icon_dir.mkdir()
            custom = icon_dir / "resync.png"
            custom.write_bytes(b"custom")
            self.assertEqual(dashboard_icon_file(data_dir, "resync"), str(custom))


if __name__ == "__main__":
    unittest.main()
