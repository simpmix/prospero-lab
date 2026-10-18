"""
BD-J Xlet Bundler.
Packages Java classes, manifests, and crafted permissionrequestfile.xml into
the compliant BD-J JAR archive. Includes synthetic bytecode generation so
tools can function even when no external JDK/javac is installed.
"""

import io
import zipfile
import struct
from pathlib import Path
from typing import Optional, Dict


PERMISSION_PROFILES = {
    "unrestricted": """<?xml version="1.0" encoding="UTF-8"?>
<permissionrequestfile xmlns="urn:bluray:bdj:permission">
    <network>
        <host>*</host>
        <port>*</port>
        <action>connect,accept,listen,resolve</action>
    </network>
    <file>
        <path>/</path>
        <action>read,write,delete,execute</action>
    </file>
    <file>
        <path>/dev/*</path>
        <action>read,write</action>
    </file>
    <file>
        <path>/system/*</path>
        <action>read</action>
    </file>
    <applifecycle>true</applifecycle>
    <property>
        <name>*</name>
        <action>read,write</action>
    </property>
</permissionrequestfile>""",
    "network": """<?xml version="1.0" encoding="UTF-8"?>
<permissionrequestfile xmlns="urn:bluray:bdj:permission">
    <network>
        <host>*</host>
        <port>*</port>
        <action>connect,accept,listen,resolve</action>
    </network>
    <applifecycle>true</applifecycle>
</permissionrequestfile>""",
    "storage": """<?xml version="1.0" encoding="UTF-8"?>
<permissionrequestfile xmlns="urn:bluray:bdj:permission">
    <file>
        <path>/</path>
        <action>read,write</action>
    </file>
    <applifecycle>true</applifecycle>
</permissionrequestfile>""",
    "minimal": """<?xml version="1.0" encoding="UTF-8"?>
<permissionrequestfile xmlns="urn:bluray:bdj:permission">
    <applifecycle>true</applifecycle>
</permissionrequestfile>""",
}
PERMISSION_REQUEST_XML_TEMPLATE = PERMISSION_PROFILES["unrestricted"]

PROBE_XLET_JAVA_SOURCE = """package prospero.research;

import java.io.*;
import java.net.*;
import java.lang.reflect.*;
import javax.tv.xlet.*;

/**
 * Prospero BD-J Security & Environment Introspection Probe
 * Researches sandbox boundaries, JNI access, and available native bridge classes.
 */
public class ProbeXlet implements Xlet {
    private XletContext context;

    public void initXlet(XletContext ctx) throws XletStateChangeException {
        this.context = ctx;
        log("[+] ProbeXlet: Initialized");
    }

    public void startXlet() throws XletStateChangeException {
        log("[+] ProbeXlet: Starting security audit...");
        auditSystemProperties();
        auditNativeLibraries();
        spawnDiagnosticsServer(9025);
    }

    public void pauseXlet() {
        log("[*] ProbeXlet: Paused");
    }

    public void destroyXlet(boolean unconditional) {
        log("[*] ProbeXlet: Destroyed");
    }

    private void auditSystemProperties() {
        String[] props = {
            "os.name", "os.arch", "os.version",
            "java.vendor", "java.version",
            "user.name", "user.home", "user.dir"
        };
        for (int i = 0; i < props.length; i++) {
            try {
                log("    [PROP] " + props[i] + " = " + System.getProperty(props[i]));
            } catch (Throwable t) {
                log("    [FAIL] Could not read " + props[i] + ": " + t.getMessage());
            }
        }
    }

    private void auditNativeLibraries() {
        // Probe for PlayStation proprietary JNI bridges
        String[] targets = {
            "com.sony.gemini.NativeBridge",
            "com.sony.orbis.NativeBridge",
            "com.sony.prospero.NativeBridge",
            "org.bluray.system.RegisterAccess"
        };
        for (int i = 0; i < targets.length; i++) {
            try {
                Class c = Class.forName(targets[i]);
                log("    [FOUND] Native class exposed: " + targets[i]);
            } catch (ClassNotFoundException e) {
                // Expected if not present
            } catch (Throwable t) {
                log("    [ERR] Probe error on " + targets[i] + ": " + t);
            }
        }
    }

    private void spawnDiagnosticsServer(final int port) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    ServerSocket server = new ServerSocket(port);
                    log("[+] Listening for research connections on port " + port);
                    while (true) {
                        Socket s = server.accept();
                        OutputStream out = s.getOutputStream();
                        out.write(("=== PROSPERO BD-J PROBE ACTIVE ===\\n").getBytes());
                        out.flush();
                        s.close();
                    }
                } catch (Throwable e) {
                    log("[-] Failed to bind socket on port " + port + ": " + e);
                }
            }
        }).start();
    }

    private void log(String msg) {
        System.out.println("[PROSPERO-LAB] " + msg);
    }
}
"""


class XletBundler:
    """
    Builds the BD-J executable JAR archive containing:
    1. MANIFEST.MF pointing to the entry Xlet class
    2. permissionrequestfile.xml for sandbox escape attempts
    3. Compiled class files or synthetic bytecode stubs
    """

    def __init__(self, xlet_class_name: str = "prospero.research.ProbeXlet", permission_profile: str = "unrestricted"):
        self.xlet_class_name = xlet_class_name
        self.permission_profile = permission_profile

    def generate_synthetic_class_bytecode(self, class_name: str = "prospero/research/ProbeXlet") -> bytes:
        """
        Synthesizes a minimal, valid Java .class file (bytecode version 49.0 - Java 5,
        compatible with CDC/BD-J Java Virtual Machines) implementing javax.tv.xlet.Xlet
        with no-op methods: initXlet, startXlet, pauseXlet, destroyXlet, <init>.
        Allows standalone generation even if no JDK is on the host.
        """
        # Bytecode generation with standard class structure
        # Magic: 0xCAFEBABE, Minor: 0, Major: 49 (Java 5)
        magic_version = struct.pack(">IHH", 0xCAFEBABE, 0, 49)

        # Constant Pool entries
        cp_entries = []

        def add_utf8(s: str) -> int:
            b = s.encode("utf-8")
            cp_entries.append(b"\x01" + struct.pack(">H", len(b)) + b)
            return len(cp_entries)

        def add_class(name_idx: int) -> int:
            cp_entries.append(b"\x07" + struct.pack(">H", name_idx))
            return len(cp_entries)

        def add_name_and_type(name_idx: int, desc_idx: int) -> int:
            cp_entries.append(b"\x0C" + struct.pack(">H", name_idx) + struct.pack(">H", desc_idx))
            return len(cp_entries)

        def add_methodref(class_idx: int, nt_idx: int) -> int:
            cp_entries.append(b"\x0A" + struct.pack(">H", class_idx) + struct.pack(">H", nt_idx))
            return len(cp_entries)

        # Build constants
        u_this_class = add_utf8(class_name)
        c_this = add_class(u_this_class)

        u_super_class = add_utf8("java/lang/Object")
        c_super = add_class(u_super_class)

        u_xlet_iface = add_utf8("javax/tv/xlet/Xlet")
        c_xlet = add_class(u_xlet_iface)

        u_init = add_utf8("<init>")
        u_void_sig = add_utf8("()V")
        nt_init = add_name_and_type(u_init, u_void_sig)
        m_super_init = add_methodref(c_super, nt_init)

        u_code = add_utf8("Code")

        # Xlet interface method names & signatures
        u_init_xlet = add_utf8("initXlet")
        u_init_xlet_sig = add_utf8("(Ljavax/tv/xlet/XletContext;)V")

        u_start_xlet = add_utf8("startXlet")
        u_pause_xlet = add_utf8("pauseXlet")
        u_destroy_xlet = add_utf8("destroyXlet")
        u_destroy_xlet_sig = add_utf8("(Z)V")

        # Pool count is 1-indexed (count + 1)
        cp_bytes = struct.pack(">H", len(cp_entries) + 1) + b"".join(cp_entries)

        # Access flags: ACC_PUBLIC (0x0001) | ACC_SUPER (0x0020)
        flags = struct.pack(">H", 0x0021)
        classes = struct.pack(">HH", c_this, c_super)

        # Interfaces: 1 interface (Xlet)
        interfaces = struct.pack(">HH", 1, c_xlet)

        # Fields: 0
        fields = struct.pack(">H", 0)

        # Helper to build a simple method with Code attribute returning void
        def build_method(name_idx: int, desc_idx: int, code_bytes: bytes, max_stack: int = 1, max_locals: int = 2) -> bytes:
            code_attr_body = struct.pack(">HHI", max_stack, max_locals, len(code_bytes)) + \
                             code_bytes + \
                             struct.pack(">HH", 0, 0)  # Exception table length (0), attributes count (0)
            code_attr = struct.pack(">HI", u_code, len(code_attr_body)) + code_attr_body
            # Method: access ACC_PUBLIC (0x0001), name_index, descriptor_index, attributes_count (1)
            method = struct.pack(">HHH", 0x0001, name_idx, desc_idx) + struct.pack(">H", 1) + code_attr
            return method

        # Constructor bytecode: aload_0 (0x2A), invokespecial Object.<init> (0xB7, index), return (0xB1)
        init_code = b"\x2a\xb7" + struct.pack(">H", m_super_init) + b"\xb1"
        m_ctor = build_method(u_init, u_void_sig, init_code, max_stack=1, max_locals=1)

        # Method bodies for Xlet: simple return (0xB1)
        void_code = b"\xb1"
        m_init_xlet = build_method(u_init_xlet, u_init_xlet_sig, void_code, max_locals=2)
        m_start_xlet = build_method(u_start_xlet, u_void_sig, void_code, max_locals=1)
        m_pause_xlet = build_method(u_pause_xlet, u_void_sig, void_code, max_locals=1)
        m_destroy_xlet = build_method(u_destroy_xlet, u_destroy_xlet_sig, void_code, max_locals=2)

        methods_count = struct.pack(">H", 5)
        methods = methods_count + m_ctor + m_init_xlet + m_start_xlet + m_pause_xlet + m_destroy_xlet

        # Class attributes: 0
        attributes = struct.pack(">H", 0)

        return magic_version + cp_bytes + flags + classes + interfaces + fields + methods + attributes

    def build_jar(self, custom_classes: Optional[Dict[str, bytes]] = None) -> bytes:
        """
        Creates the JAR binary bytes in memory.
        """
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # Manifest
            manifest_content = (
                f"Manifest-Version: 1.0\r\n"
                f"Main-Class: {self.xlet_class_name}\r\n"
                f"Xlet-Class: {self.xlet_class_name}\r\n"
                f"Created-By: prospero-lab\r\n\r\n"
            )
            zf.writestr("META-INF/MANIFEST.MF", manifest_content.encode("utf-8"))

            # BD-J Permission Request File
            xml_content = PERMISSION_PROFILES.get(self.permission_profile, PERMISSION_PROFILES["unrestricted"])
            zf.writestr("META-INF/permissionrequestfile.xml", xml_content.encode("utf-8"))
            zf.writestr("BDMV/META-INF/permissionrequestfile.xml", xml_content.encode("utf-8"))

            # Classes
            if custom_classes:
                for path_in_jar, class_bytes in custom_classes.items():
                    zf.writestr(path_in_jar, class_bytes)
            else:
                # Use synthetic bytecode for self-contained operation
                class_rel_path = self.xlet_class_name.replace(".", "/") + ".class"
                synthetic_class = self.generate_synthetic_class_bytecode(self.xlet_class_name.replace(".", "/"))
                zf.writestr(class_rel_path, synthetic_class)

        return buf.getvalue()

    def write_jar_to_bdmv(self, jar_dir: Path, filename: str = "00000.jar") -> Path:
        """
        Writes the generated JAR file into the BDMV/JAR directory.
        """
        jar_dir.mkdir(parents=True, exist_ok=True)
        target = jar_dir / filename
        target.write_bytes(self.build_jar())
        return target
