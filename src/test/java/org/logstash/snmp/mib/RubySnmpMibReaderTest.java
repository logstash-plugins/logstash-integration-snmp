package org.logstash.snmp.mib;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.logstash.snmp.LoggerAppenderExtension;
import org.snmp4j.smi.OID;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.logstash.snmp.Resources.path;

class RubySnmpMibReaderTest {
    private static final Path RFC1213_MIB = path("RFC1213-MIB.yaml");
    private static final Path ACCOUNTING_CONTROL_MIB = path("ACCOUNTING-CONTROL-MIB.yaml");
    private static final Path INVALID_MIB = path("INVALID-MIB.yaml");
    private static final Path INVALID_OID_MIB = path("INVALID-OID-MIB.yaml");

    @RegisterExtension
    LoggerAppenderExtension loggerExt = new LoggerAppenderExtension(LogManager.getLogger(RubySnmpMibReader.class));

    private final RubySnmpMibReader reader = new RubySnmpMibReader();

    @Test
    void shouldReadValidMibYamlFiles() {
        final Map<OID, OidData> result = new HashMap<>();

        reader.read(List.of(RFC1213_MIB, ACCOUNTING_CONTROL_MIB), result::put);

        assertFalse(result.isEmpty());

        final Map<String, List<OidData>> mibsByModuleName = result.values()
                .stream()
                .collect(Collectors.groupingBy(OidData::getModuleName));

        assertEquals(201, mibsByModuleName.remove("RFC1213-MIB").size());
        assertEquals(45, mibsByModuleName.remove("ACCOUNTING-CONTROL-MIB").size());
        assertTrue(mibsByModuleName.isEmpty());
    }

    @Test
    void shouldThrowInvalidMbiWhenFileContentIsInvalid() {
        final List<Path> paths = List.of(INVALID_MIB);
        final InvalidMbiFileException exception = assertThrows(
                InvalidMbiFileException.class,
                () -> reader.read(paths, (oid, oidData) -> {
                })
        );

        assertEquals(String.format("Error reading MIB file: %s", INVALID_MIB), exception.getMessage());
    }

    @Test
    void shouldWarnWhenMibFileHasInvalidOids() {
        final Map<OID, OidData> result = new HashMap<>();

        reader.read(List.of(INVALID_OID_MIB), result::put);

        loggerExt.getAppender().assertLogWithFormat(
                RubySnmpMibReader.class,
                Level.WARN,
                "The MIB file `{}` has an invalid OID value `{}`. Skipping"
        );

        assertFalse(result.isEmpty());
        assertNotNull(result.get(new OID("1.3.6.1.2.1.60.1")));
    }
}