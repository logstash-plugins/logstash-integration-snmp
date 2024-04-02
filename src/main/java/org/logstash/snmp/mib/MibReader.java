package org.logstash.snmp.mib;

import org.snmp4j.smi.OID;

import java.nio.file.Path;
import java.util.List;
import java.util.function.BiConsumer;

interface MibReader {
    void read(List<Path> path, BiConsumer<OID, OidData> consumer) throws InvalidMibFileException;
}
