package org.logstash.snmp.mib;

import org.logstash.snmp.DefaultOidFieldMapper;
import org.logstash.snmp.OidFieldMapper;
import org.logstash.snmp.OidFieldMapper.ResolvedIdentifier;
import org.snmp4j.smi.OID;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class MibManager {
    private final OidTrie oidTrie;
    private final OidFieldMapper fieldMapper;
    private final Map<String, MibReader> mibFileReaders;

    public MibManager() {
        this(new DefaultOidFieldMapper(0, 0));
    }

    public MibManager(OidFieldMapper fieldMapper) {
        this(new OidTrie(), fieldMapper, Map.of(
                SmilibPythonMibReader.FILE_EXTENSION, new SmilibPythonMibReader(),
                RubySnmpMibReader.FILE_EXTENSION, new RubySnmpMibReader()
        ));
    }

    MibManager(OidTrie oidTrie, OidFieldMapper fieldMapper, Map<String, MibReader> mibFileReaders) {
        this.oidTrie = oidTrie;
        this.fieldMapper = fieldMapper;
        this.mibFileReaders = mibFileReaders;
    }

    public void add(String path) throws IOException {
        try (final Stream<Path> allFilesMib = Files.walk(Path.of(path))) {
            // Due to the OID overrides, it should group the files sorted by path, so the
            // map results are deterministic, independently of OS and path walk order.
            final Map<String, Collection<Path>> filesPerExtension = allFilesMib
                    .filter(Files::isRegularFile)
                    .collect(Collectors.groupingBy(
                            FileUtils::getFileExtension,
                            HashMap::new,
                            Collectors.toCollection(TreeSet::new))
                    );

            filesPerExtension.forEach((extension, files) -> {
                if (mibFileReaders.containsKey(extension)) {
                    mibFileReaders.get(extension).read(files, oidTrie::insert);
                }
            });
        }

        // Ensure the root ISO OID is always mapped
        final OID isoOid = new OID("1");
        if (oidTrie.find(isoOid).isEmpty()) {
            oidTrie.insert(isoOid, new OidData("node", "iso", "logstash"));
        }
    }

    public String map(final OID oid) {
        final List<ResolvedIdentifier> resolvedIdentifiers = new ArrayList<>(oid.getValue().length);
        this.oidTrie.find(
                oid,
                node -> resolvedIdentifiers.add(new ResolvedIdentifier(node.getIdentifier(), node.getData()))
        );
        return fieldMapper.map(oid, resolvedIdentifiers.toArray(ResolvedIdentifier[]::new));
    }

    Map<String, MibReader> getMibFileReaders() {
        return Collections.unmodifiableMap(mibFileReaders);
    }

    OidFieldMapper getFieldMapper() {
        return fieldMapper;
    }
}
