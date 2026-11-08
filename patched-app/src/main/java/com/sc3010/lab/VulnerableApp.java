package com.sc3010.lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * SC3010 Log4Shell teaching lab -- victim application.
 *
 * This program does ONE interesting thing: it takes a string it does not
 * control (a command-line argument, falling back to the LOG_INPUT env var)
 * and writes it to a log with Log4j. That is all. There is no "execute"
 * call anywhere in this file.
 *
 * The whole point of CVE-2021-44228 is that, with a vulnerable Log4j, the
 * act of *logging* an attacker-controlled string is enough to trigger
 * remote code execution, because Log4j performs lookup substitution on the
 * message text before (really, while) formatting it.
 *
 * The vulnerable-app and patched-app contain this identical source file.
 * The ONLY difference between the two experiments is the Log4j version
 * declared in pom.xml (2.14.1 vs 2.17.1).
 */
public class VulnerableApp {

    private static final Logger logger = LogManager.getLogger(VulnerableApp.class);

    public static void main(String[] args) {
        System.out.println("[APP] VulnerableApp starting (SC3010 Log4Shell lab)");

        // Read the untrusted input: first CLI arg, else env var, else a default.
        String input;
        if (args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            input = args[0];
        } else {
            String env = System.getenv("LOG_INPUT");
            input = (env != null) ? env : "no input provided";
        }

        System.out.println("[APP] About to log untrusted input (length=" + input.length() + ")");

        // THE VULNERABLE OPERATION.
        // We simply log the string. We do not parse it, evaluate it, or run it.
        // On vulnerable Log4j, lookup substitution turns ${jndi:...} in this
        // message into a JNDI lookup -> remote class load -> code execution.
        logger.error("Processing user input: " + input);

        System.out.println("[APP] app finished (control returned to main)");
    }
}
