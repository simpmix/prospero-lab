import unittest
from prospero_lab.simulator.mock_runtime import (
    MockRuntime,
    PROT_READ,
    PROT_WRITE,
    PROT_EXEC,
)
from prospero_lab.xom.blind_rop import ROPChainBuilder


class TestSimulator(unittest.TestCase):
    def test_mock_runtime_rop_execution(self):
        vm = MockRuntime()
        addr_pop_rdi = 0x1000
        addr_pop_rax = 0x2000
        addr_syscall = 0x3000

        vm.register_gadget(
            addr_pop_rdi,
            "pop rdi; ret",
            lambda rt: setattr(rt.cpu, "rdi", rt.read_qword(rt.cpu.rsp, allow_xom=True))
            or setattr(rt.cpu, "rsp", rt.cpu.rsp + 8),
        )
        vm.register_gadget(
            addr_pop_rax,
            "pop rax; ret",
            lambda rt: setattr(rt.cpu, "rax", rt.read_qword(rt.cpu.rsp, allow_xom=True))
            or setattr(rt.cpu, "rsp", rt.cpu.rsp + 8),
        )
        vm.register_gadget(addr_syscall, "syscall; ret", lambda rt: None)

        # Build chain: rdi = 0x1337, rax = 4 (write) -> syscall
        builder = ROPChainBuilder({
            "pop_rdi": addr_pop_rdi,
            "pop_rax": addr_pop_rax,
            "syscall": addr_syscall,
        })
        builder.pop_rdi(0x1337)
        builder.pop_rax(4)
        builder.syscall()

        payload = builder.serialize()
        vm.load_rop_chain(0x7000, payload)

        traces = vm.run_rop()
        self.assertEqual(len(traces), 3)
        self.assertEqual(vm.cpu.rdi, 0x1337)
        self.assertEqual(len(vm.syscall_log), 1)
        self.assertEqual(vm.syscall_log[0]["syscall_number"], 4)

    def test_xom_memory_protection(self):
        vm = MockRuntime()
        # Map XOM region (EXEC without READ)
        vm.map_region(0x5000, 0x1000, prot=PROT_EXEC, name="xom_code")

        # Attempt to read data as normal memory without allow_xom
        with self.assertRaises(PermissionError):
            vm.read_qword(0x5000, allow_xom=False)


if __name__ == "__main__":
    unittest.main()
