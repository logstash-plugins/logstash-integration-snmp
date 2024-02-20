package org.logstash.snmp.mib;

import org.logstash.snmp.DefaultOidFieldMapper;
import org.logstash.snmp.OidFieldMapper;
import org.snmp4j.smi.OID;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
            final Map<String, List<Path>> filesPerExtension = allFilesMib
                    .filter(Files::isRegularFile)
                    .collect(Collectors.groupingBy(FileUtils::getFileExtension));

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
        final List<String> resolvedIdentifiers = new ArrayList<>(oid.getValue().length);
        final Optional<OidData> data = this.oidTrie.find(
                oid,
                node -> resolvedIdentifiers.add(node.hasData() ? node.getData().getName() : String.valueOf(node.getIdentifier()))
        );

        return fieldMapper.map(oid, resolvedIdentifiers.toArray(new String[0]), data.orElse(null));
    }

    Map<String, MibReader> getMibFileReaders() {
        return Collections.unmodifiableMap(mibFileReaders);
    }
}
