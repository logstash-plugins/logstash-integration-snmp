package org.logstash.snmp.mib;

import org.snmp4j.smi.OID;

import java.nio.file.Path;
import java.util.Collection;
import java.util.function.BiConsumer;

interface MibReader {
    void read(Collection<Path> path, BiConsumer<OID, OidData> consumer) throws InvalidMibFileException;
}
