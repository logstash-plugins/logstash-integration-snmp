package org.logstash.snmp.mib;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.logstash.snmp.LoggerAppenderExtension;
import org.snmp4j.smi.OID;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Stack;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidTrieTest {

    @RegisterExtension
    LoggerAppenderExtension loggerExt = new LoggerAppenderExtension(LogManager.getLogger(OidTrie.class));

    private final OidTrie oidTrie = new OidTrie();

    @Test
    void insertShouldNotLogWhenFirstAddingOid() {
        oidTrie.insert(new OID("1.3.6.1.2.1.60.2"), new OidData("node", "foo", "DUMMY"));

        assertTrue(loggerExt.getAppender().isEmpty());
    }

    @Test
    void insertShouldNotLogWhenOverridingWithSameData() {
        oidTrie.insert(new OID("1.3.6.1.2.1.60.2"), new OidData("node", "foo", "DUMMY"));
        oidTrie.insert(new OID("1.3.6.1.2.1.60.2"), new OidData("node", "foo", "DUMMY"));

        assertTrue(loggerExt.getAppender().isEmpty());
    }

    @Test
    void insertShouldNotLogWhenOverridingWithSameDataButDifferentModule() {
        oidTrie.insert(new OID("1.3.6.1.2.1.60.2"), new OidData("node", "foo", "FOO"));
        oidTrie.insert(new OID("1.3.6.1.2.1.60.2"), new OidData("node", "foo", "BAR"));

        assertTrue(loggerExt.getAppender().isEmpty());
    }

    @Test
    void insertShouldLogWhenOidDataIsOverridden() {
        final OID oid = new OID("1.3.6.1.2.1.60.2");
        final OidData newestOidData = new OidData("node", "second", "DUMMY");

        oidTrie.insert(oid, new OidData("notification", "first", "FOO"));
        oidTrie.insert(oid, newestOidData);

        loggerExt.getAppender().assertLogWithMessage(
                OidTrie.class,
                Level.WARN,
                "warning: overwriting MIB OID '1.3.6.1.2.1.60.2' and name 'first' with new name 'second' from module 'DUMMY'"
        );
    }

    @Test
    void insertShouldReplaceOidDataWhenOidIsOverridden() {
        final OID oid = new OID("1.3.6.1.2.1.60.2");
        final OidData newestOidData = new OidData("node", "second", "DUMMY");

        oidTrie.insert(oid, new OidData("notification", "first", "FOO"));
        oidTrie.insert(oid, newestOidData);

        final OidData oidData = oidTrie.find(oid).orElseThrow();
        assertEquals(oidData, newestOidData);
    }

    @Test
    void insertShouldNotReplaceOidDataWhenOtherModuleValuesAreEquals() {
        final OID oid = new OID("1.3.6.1.2.1.60.2");
        final OidData firstOidData = new OidData("node", "first", "OLD");

        oidTrie.insert(oid, firstOidData);
        oidTrie.insert(oid, new OidData("node", "first", "NEW"));

        final OidData oidData = oidTrie.find(oid).orElseThrow();
        assertEquals(oidData, firstOidData);
    }

    @Test
    void findShouldReturnOnlyExistingOid() {
        final OID fooOid = new OID("1.3.6.1.2.1.60.2");
        final OID barOid = new OID("1.3.6.1.2.1.60.2.0");

        final OidData fooData = new OidData("node", "foo", "DUMMY");
        final OidData barData = new OidData("notification", "bar", "OTHER");

        oidTrie.insert(fooOid, fooData);
        oidTrie.insert(barOid, barData);

        assertTrue(oidTrie.find(new OID("1.3.6.1.2.1.60")).isEmpty());
        assertEquals(fooData, oidTrie.find(fooOid).orElseThrow());
        assertEquals(barData, oidTrie.find(barOid).orElseThrow());
    }

    @Test
    void findShouldConsumeAllExistingOidEdgesIdentifiers() {
        final OID oid = new OID("1.3.6.1.2.1.60.2");
        final Stack<Integer> stack = new Stack<>();
        for (int i = oid.getValue().length - 1; i >= 0; i--) {
            stack.push(oid.get(i));
        }

        oidTrie.insert(oid, new OidData("node", "value", "FOO"));
        oidTrie.find(oid, node -> assertEquals(stack.pop().intValue(), node.getIdentifier()));

        assertTrue(stack.isEmpty());
    }

    @Test
    void finsShouldConsumePartialExistingOidEdgesIdentifiers() {
        final OID partialOid = new OID("1.3.6.1.2.1.60.2");
        final Stack<Integer> stack = new Stack<>();
        for (int i = partialOid.getValue().length - 1; i >= 0; i--) {
            stack.push(partialOid.get(i));
        }

        oidTrie.insert(new OID(partialOid).append(1), new OidData("node", "value", "FOO"));
        oidTrie.find(partialOid, node -> assertEquals(stack.pop().intValue(), node.getIdentifier()));

        assertTrue(stack.isEmpty());
    }

    @Test
    void shouldFindAllProvidedDicMibsOids() throws IOException {
        final List<Path> allMibs;
        try (final Stream<Path> mibs = Files.walk(Paths.get("lib/mibs").toAbsolutePath())) {
            allMibs = mibs.filter(p -> Files.isRegularFile(p) && FileUtils.getFileExtension(p).equals("dic"))
                    .collect(Collectors.toList());
        }

        final SmilibPythonMibReader reader = new SmilibPythonMibReader();
        final List<OID> readOids = new ArrayList<>();

        reader.read(allMibs, (oid, oidData) -> {
            oidTrie.insert(oid, oidData);
            readOids.add(oid);
        });

        final boolean missingOids = readOids
                .stream()
                .anyMatch(oid -> oidTrie.find(oid).isEmpty());

        assertFalse(missingOids);
    }
}