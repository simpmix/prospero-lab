import unittest
from prospero_lab.reporting.dashboard import DashboardGenerator


class TestDashboard(unittest.TestCase):
    def test_dashboard_generation(self):
        gen = DashboardGenerator()
        html = gen.generate_html()

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("ProsperoLab Security Console", html)
        self.assertIn("sys_namedobj_create", html)
        self.assertIn("KMD_IOCTL_SUBMIT_COMMAND_BUFFER", html)
        self.assertIn("Syzkaller Grammar", html)


if __name__ == "__main__":
    unittest.main()
