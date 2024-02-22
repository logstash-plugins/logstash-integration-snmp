package org.logstash.snmp.mib;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.snmp4j.smi.OID;
import org.yaml.snakeyaml.Yaml;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

class RubySnmpMibReader implements MibReader {
    private static final Logger logger = LogManager.getLogger(RubySnmpMibReader.class);
    static final String FILE_EXTENSION = "yaml";

    @Override
    public void read(final List<Path> paths, final BiConsumer<OID, OidData> consumer) throws InvalidMibFileException {
        final Yaml yaml = new Yaml();
        for (final Path path : paths) {
            final Map<String, String> configMap;
            try {
                configMap = yaml.load(Files.newBufferedReader(path));
            } catch (Exception e) {
                throw new InvalidMibFileException(String.format("Error reading MIB file: %s", path), e);
            }

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
}
