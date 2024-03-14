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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.logstash.snmp.Resources.path;

class SmilibPythonMibReaderTest {
    private static final Path RFC1213_MIB = path("RFC1213-MIB.dic");
    private static final Path ACCOUNTING_CONTROL_MIB = path("ACCOUNTING-CONTROL-MIB.dic");
    private static final Path NO_NODES_MIB = path("NO-NODES-MIB.dic");
    private static final Path INVALID_MIB = path("INVALID-MIB.dic");
    private static final Path INVALID_OID_MIB = path("INVALID-OID-MIB.dic");
    private static final Path NODE_WITHOUT_OID_MIB = path("NODE-WITHOUT-OID-MIB.dic");

    @RegisterExtension
    LoggerAppenderExtension loggerExt = new LoggerAppenderExtension(LogManager.getLogger(SmilibPythonMibReader.class));

    private final SmilibPythonMibReader reader = new SmilibPythonMibReader();

    @Test
    void shouldReadValidMibDicFile() {
        final Map<OID, OidData> result = new HashMap<>();

        reader.read(List.of(RFC1213_MIB), result::put);

        assertEquals(201, result.size());
        assertTrue(result.values().stream().map(OidData::getModuleName).allMatch("RFC1213-MIB"::equals));
    }

    @Test
    void shouldReadNotificationOids() {
        final String moduleName = "ACCOUNTING-CONTROL-MIB";
        final String notificationType = "notification";
        final Map<OID, OidData> result = new HashMap<>();

        reader.read(List.of(ACCOUNTING_CONTROL_MIB), result::put);

        assertOidDataExists(result, new OID("1.3.6.1.2.1.60.2.0.1"), moduleName, "acctngFileNearlyFull", notificationType);
        assertOidDataExists(result, new OID("1.3.6.1.2.1.60.2.0.2"), moduleName, "acctngFileFull", notificationType);
    }

    @Test
    void shouldWarnWhenMibFileHasNoNodesDefined() {
        reader.read(List.of(NO_NODES_MIB), (oid, oidData) -> {
        });

        loggerExt.getAppender().assertLogWithFormat(
                SmilibPythonMibReader.class,
                Level.WARN,
                "The MIB file `{}` does not contain any node definition. Skipping"
        );
    }

    @Test
    void shouldWarnWhenMibFileHasInvalidOid() {
        final Map<OID, OidData> result = new HashMap<>();

        reader.read(List.of(INVALID_OID_MIB), result::put);

        loggerExt.getAppender().assertLogWithFormat(
                SmilibPythonMibReader.class,
                Level.WARN,
                "The MIB file `{}` node `{}` has an invalid OID value `{}`. Skipping"
        );

        assertFalse(result.isEmpty());
        assertNotNull(result.get(new OID("1.3.6.1.2.1.60.1")));
    }

    @Test
    void shouldWarnWhenMibFileHasNodesWithoutOidValue() {
        final Map<OID, OidData> result = new HashMap<>();

        reader.read(List.of(NODE_WITHOUT_OID_MIB), result::put);

        loggerExt.getAppender().assertLogWithFormat(
                SmilibPythonMibReader.class,
                Level.WARN,
                "The MIB file `{}` node `{}` has no defined OID. Skipping"
        );

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldReadAllProvidedDicMibs() throws IOException {
        final List<Path> allMibs;
        try (final Stream<Path> mibs = Files.walk(Paths.get("lib/mibs").toAbsolutePath())) {
            allMibs = mibs
                    .filter(p -> Files.isRegularFile(p) && FileUtils.getFileExtension(p).equals("dic"))
                    .collect(Collectors.toList());
        }

        final int expectedOids = 22426;
        final Map<OID, OidData> result = new HashMap<>(expectedOids);

        reader.read(allMibs, result::put);

        assertEquals(expectedOids, result.size());
    }

    @Test
    void shouldThrowInvalidMbiWhenFileContentIsInvalid() {
        final List<Path> paths = List.of(INVALID_MIB);
        final InvalidMibFileException exception = assertThrows(
                InvalidMibFileException.class,
                () -> reader.read(paths, (oid, oidData) -> {})
        );

        assertEquals(String.format("Error parsing MIB file: %s", INVALID_MIB), exception.getMessage());
    }

    private void assertOidDataExists(Map<OID, OidData> result, OID oid, String moduleName, String name, String type) {
        final OidData oidData = result.get(oid);
        assertNotNull(oidData, String.format("%s with OID %s not read/found on the module %s file", type, oid.toString(), moduleName));
        assertEquals(moduleName, oidData.getModuleName());
        assertEquals(name, oidData.getName());
        assertEquals(type, oidData.getType());
    }
}