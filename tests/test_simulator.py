import unittest
from prospero_lab.simulator.mock_runtime import (
    MockRuntime,
    PROT_READ,
    PROT_WRITE,
    PROT_EXEC,
)
from prospero_lab.exceptions import XOMViolationError, WXPViolationError
from prospero_lab.xom.gadget_analyzer import Gadget
from prospero_lab.xom.blind_rop import ROPChainBuilder


class TestSimulator(unittest.TestCase):
    def test_mock_runtime_auto_gadgets(self):
        vm = MockRuntime()
        gadgets = [
            Gadget(0x1000, 0, b"\x5f\xc3", "pop rdi; ret", "arg1_setup", "REGISTER_LOAD", 9),
            Gadget(0x2000, 0, b"\x58\xc3", "pop rax; ret", "rax_setup", "REGISTER_LOAD", 9),
            Gadget(0x3000, 0, b"\x0f\x05\xc3", "syscall; ret", "syscall_invoke", "SYSCALL", 10),
        ]
        vm.load_gadgets_from_analyzer(gadgets)

        # Build chain: rdi = 0x1337, rax = 608 (sys_evf_create) -> syscall
        builder = ROPChainBuilder({
            "pop_rdi": 0x1000,
            "pop_rax": 0x2000,
            "syscall": 0x3000,
        })
        builder.pop_rdi(0x1337)
        builder.pop_rax(608)
        builder.syscall()

        payload = builder.serialize()
        vm.load_rop_chain(0x7000, payload)

        traces = vm.run_rop()
        self.assertEqual(len(traces), 3)
        self.assertEqual(vm.cpu.rdi, 0x1337)
        self.assertEqual(len(vm.syscall_log), 1)
        self.assertEqual(vm.syscall_log[0]["syscall_number"], 608)
        self.assertIn(100, vm.active_event_flags)

    def test_xom_memory_protection(self):
        vm = MockRuntime()
        vm.map_region(0x5000, 0x1000, prot=PROT_EXEC, name="xom_code")

        with self.assertRaises(XOMViolationError):
            vm.read_qword(0x5000, allow_xom=False)

    def test_wx_violation(self):
        vm = MockRuntime(enforce_wx=True)
        # Map a writable and executable page
        vm.map_region(0x9000, 0x1000, prot=PROT_READ | PROT_WRITE | PROT_EXEC, name="wx_page")
        vm.register_gadget(0x9000, "nop; ret", lambda rt: None)

        # Place gadget address on fake stack
        fake_stack = 0x8000
        vm.map_region(fake_stack, 0x1000, prot=PROT_READ | PROT_WRITE, name="stack")
        vm.write_qword(fake_stack, 0x9000)
        vm.cpu.rsp = fake_stack

        with self.assertRaises(WXPViolationError):
            vm.run_rop()


if __name__ == "__main__":
    unittest.main()
