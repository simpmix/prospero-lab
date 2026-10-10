package prospero.research;

import java.io.*;
import java.net.*;
import javax.tv.xlet.*;

/**
 * ProsperoLab Reference BD-J Probe Xlet.
 * Demonstrates environment auditing, JNI bridge detection,
 * and diagnostic socket creation.
 */
public class ProbeXlet implements Xlet {
    private XletContext context;

    public void initXlet(XletContext ctx) throws XletStateChangeException {
        this.context = ctx;
        System.out.println("[+] ProbeXlet: Initialized.");
    }

    public void startXlet() throws XletStateChangeException {
        System.out.println("[+] ProbeXlet: Starting system audit...");
        auditSystemProperties();
        probeNativeBridges();
    }

    public void pauseXlet() {
        System.out.println("[*] ProbeXlet: Paused.");
    }

    public void destroyXlet(boolean unconditional) {
        System.out.println("[*] ProbeXlet: Destroyed.");
    }

    private void auditSystemProperties() {
        String[] keys = {"os.name", "os.arch", "os.version", "java.version", "user.name"};
        for (int i = 0; i < keys.length; i++) {
            try {
                System.out.println("    [PROP] " + keys[i] + " = " + System.getProperty(keys[i]));
            } catch (Throwable t) {
                System.out.println("    [ERR] Cannot read " + keys[i]);
            }
        }
    }

    private void probeNativeBridges() {
        String[] targets = {
            "com.sony.gemini.NativeBridge",
            "com.sony.orbis.NativeBridge",
            "com.sony.prospero.NativeBridge"
        };
        for (int i = 0; i < targets.length; i++) {
            try {
                Class c = Class.forName(targets[i]);
                System.out.println("    [FOUND] Native class: " + targets[i]);
            } catch (ClassNotFoundException e) {
                // Not found
            }
        }
    }
}
