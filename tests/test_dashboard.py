import unittest
from prospero_lab.reporting.dashboard import DashboardGenerator


class TestDashboard(unittest.TestCase):
    def test_dashboard_generation(self):
        gen = DashboardGenerator()
        html = gen.generate_html()

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("ProsperoLab Security Audit", html)
        self.assertIn("sys_namedobj_create", html)
        self.assertIn("Automated Syzkaller Fuzzer Grammar", html)


if __name__ == "__main__":
    unittest.main()
