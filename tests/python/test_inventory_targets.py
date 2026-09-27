"""The web app's Servers › targets.txt read back by the CLI (stdlib unittest; no network).

tests/fixtures/inventory-targets.txt is exactly what views/inventory.js targetsText() writes for
server names with spaces, '#', '//', ';', '=' and control characters (tests/js/ui-dom.test.js
asserts that). The CLI must read one server per line, each with only its own addresses.

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'ssl_origin_scan.py'
TARGETS = ROOT / 'tests' / 'fixtures' / 'inventory-targets.txt'


def _load_cli():
    if 'ssl_origin_scan' in sys.modules:
        return sys.modules['ssl_origin_scan']
    spec = importlib.util.spec_from_file_location('ssl_origin_scan', str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules['ssl_origin_scan'] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


sos = _load_cli()


class InventoryTargetsRoundTrip(unittest.TestCase):
    def test_every_server_keeps_its_own_addresses(self):
        inventory = sos.parse_inventory(TARGETS.read_text(encoding='utf-8'), str(TARGETS))
        self.assertEqual(inventory.warnings, [])
        got = [(s.name, list(s.ips), list(s.hostnames)) for s in inventory.servers]
        self.assertEqual(got, [
            ('Web_Server_1', ['192.0.2.11'], []),
            ('Web_Server_2', ['192.0.2.12'], []),
            ('_bastion', ['192.0.2.13'], []),
            ('[prod]_api', ['192.0.2.14'], []),
            ('Web_2', ['198.51.100.2'], []),
            ('_legacy', ['198.51.100.3'], []),
            ('db_backup', ['198.51.100.4'], []),
            ('role_web', ['198.51.100.5'], []),
            ('db_primary', ['203.0.113.1', '2001:db8::1'], []),
            ('db_replica', ['203.0.113.2'], []),
            ('rack_web', ['203.0.113.3'], []),
            ('203.0.113.9', ['203.0.113.9'], []),
        ])


if __name__ == '__main__':
    unittest.main()
