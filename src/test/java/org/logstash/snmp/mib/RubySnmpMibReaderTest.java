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

class RubySnmpMibReaderTest {
    private static final Path RUBY_SNMP_PROVIDED_MIBS = Path.of("lib/mibs/ruby-snmp").toAbsolutePath();
    private static final Path RFC1213_MIB = RUBY_SNMP_PROVIDED_MIBS.resolve("RFC1213-MIB.yaml");
    private static final Path INVALID_MIB = path("INVALID-MIB.yaml");
    private static final Path INVALID_OID_MIB = path("INVALID-OID-MIB.yaml");

    @RegisterExtension
    LoggerAppenderExtension loggerExt = new LoggerAppenderExtension(LogManager.getLogger(RubySnmpMibReader.class));

    private final RubySnmpMibReader reader = new RubySnmpMibReader();

    @Test
    void shouldReadValidMibYamlFile() {
        final Map<OID, OidData> result = new HashMap<>();

        reader.read(List.of(RFC1213_MIB), result::put);

        assertEquals(201, result.size());
        assertTrue(result.values().stream().map(OidData::getModuleName).allMatch("RFC1213-MIB"::equals));
    }

    @Test
    void shouldThrowInvalidMbiWhenFileContentIsInvalid() {
        final List<Path> paths = List.of(INVALID_MIB);
        final InvalidMbiFileException exception = assertThrows(
                InvalidMbiFileException.class,
                () -> reader.read(paths, (oid, oidData) -> {})
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

    @Test
    void shouldReadAllProvidedYamlMibs() throws IOException {
        final List<Path> allMibs;
        try (final Stream<Path> mibs = Files.walk(RUBY_SNMP_PROVIDED_MIBS)) {
            allMibs = mibs
                    .filter(p -> Files.isRegularFile(p) && FileUtils.getFileExtension(p).equals("yaml"))
                    .collect(Collectors.toList());
        }

        final int expectedOids = 20041;
        final Map<OID, OidData> result = new HashMap<>(expectedOids);

        reader.read(allMibs, result::put);

        assertEquals(expectedOids, result.size());
    }
}