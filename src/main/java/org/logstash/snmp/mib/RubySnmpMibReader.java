package org.logstash.snmp.mib;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;
import org.snmp4j.smi.OID;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

class RubySnmpMibReader implements MibReader {
    private static final Logger logger = LogManager.getLogger(RubySnmpMibReader.class);
    private static final LoadSettings LOAD_SETTINGS = LoadSettings.builder().build();

    static final String FILE_EXTENSION = "yaml";

    @Override
    public void read(final List<Path> paths, final BiConsumer<OID, OidData> consumer) throws InvalidMibFileException {
        for (final Path path : paths) {
            final Map<String, String> configMap = loadYamlFile(path);

            final String moduleName = FileUtils.getFileNameWithoutExtension(path);
            for (final Map.Entry<String, String> entry : configMap.entrySet()) {
                final OID oid;
                try {
                    oid = new OID(entry.getValue());
                } catch (RuntimeException e) {
                    logger.warn("The MIB file `{}` has an invalid OID value `{}`. Skipping", path, entry.getValue());
                    continue;
                }

                consumer.accept(oid, new OidData("node", entry.getKey(), moduleName));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> loadYamlFile(Path file) {
        final Load yaml = new Load(LOAD_SETTINGS);
        try {
            return (Map<String, String>) yaml.loadFromReader(Files.newBufferedReader(file));
        } catch (Exception e) {
            throw new InvalidMibFileException(String.format("Error reading MIB file: %s", file), e);
        }
    }
}
