import unittest
from prospero_lab.kernel.syscall_table import get_all_syscalls, PROSPERO_SYSCALLS, FREEBSD_SYSCALLS
from prospero_lab.kernel.surface_auditor import KernelSurfaceAuditor


class TestKernel(unittest.TestCase):
    def test_syscall_database(self):
        all_sys = get_all_syscalls()
        self.assertGreater(len(all_sys), len(FREEBSD_SYSCALLS))
        self.assertIn(454, all_sys)  # _umtx_op
        self.assertIn(608, all_sys)  # sys_evf_create
        self.assertIn(585, all_sys)  # sys_namedobj_create

    def test_surface_auditor(self):
        auditor = KernelSurfaceAuditor()
        report = auditor.audit_attack_surface()

        self.assertIn("critical_race_uaf_targets", report)
        self.assertIn("aslr_bypass_targets", report)
        self.assertGreater(len(report["critical_race_uaf_targets"]), 0)

        syzkaller_defs = auditor.generate_syzkaller_descriptions()
        self.assertIn("sys_evf_create", syzkaller_defs)
        self.assertIn("_umtx_op", syzkaller_defs)


if __name__ == "__main__":
    unittest.main()
