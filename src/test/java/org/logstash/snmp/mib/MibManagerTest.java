package org.logstash.snmp.mib;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.logstash.snmp.OidFieldMapper;
import org.logstash.snmp.Resources;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.snmp4j.smi.OID;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MibManagerTest {
    @Mock
    private OidTrie oidTrie;
    @Mock
    private OidFieldMapper oidFieldMapper;
    @Mock
    private MibReader dicMibReader;
    @Mock
    private MibReader yamlMibReader;

    private MibManager mibManager;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.initMocks(this);
        final Map<String, MibReader> fileReaders = Map.of(
                "dic", dicMibReader,
                "yaml", yamlMibReader
        );
        mibManager = new MibManager(oidTrie, oidFieldMapper, fileReaders);
    }

    @Test
    void addShouldReadMibFilesUsingCorrectExtensionReader() throws IOException {
        when(oidTrie.find(any()))
                .thenReturn(Optional.empty());

        mibManager.add(Resources.fullPath("mib-manager-test"));

        final Path dicPath = Resources.path("mib-manager-test/DIC-MIB.dic");
        final Path dic2Path = Resources.path("mib-manager-test/DIC-MIB-2.dic");

        final Path yamlPath = Resources.path("mib-manager-test/YAML-MIB.yaml");
        final Path yaml2Path = Resources.path("mib-manager-test/YAML-MIB-2.yaml");

        verify(dicMibReader)
                .read(argThat(p -> p.size() == 2 && p.containsAll(List.of(dic2Path, dicPath))), any());

        verify(yamlMibReader)
                .read(argThat(p -> p.size() == 2 && p.containsAll(List.of(yamlPath, yaml2Path))), any());
    }

    @Test
    void addShouldIncludeDefaultIsoOid() throws IOException {
        final OID isoOid = new OID("1");

        when(oidTrie.find(isoOid))
                .thenReturn(Optional.empty());

        final Path dicPath = Resources.path("mib-manager-test/DIC-MIB.dic");

        mibManager.add(dicPath.toString());

        verify(oidTrie)
                .insert(eq(isoOid), argThat(p -> "iso".equals(p.getName())));
    }


    @Test
    void addShouldReadFilesInOrder(@TempDir Path tempDir) throws IOException {
        final Path first = Files.createTempFile(tempDir, "A", ".dic");
        final Path second = Files.createTempFile(tempDir, "B", ".dic");
        final Path third = Files.createTempFile(tempDir, "F", ".dic");
        final Path fourth = Files.createTempFile(tempDir, "Z", ".dic");

        final ArgumentCaptor<Collection<Path>> filesCaptor = ArgumentCaptor.captor();

        doNothing().when(dicMibReader)
                .read(filesCaptor.capture(), any());

        mibManager.add(tempDir.toString());

        final Iterator<Path> fileReadOrder = filesCaptor.getValue().iterator();
        assertEquals(fileReadOrder.next(), first);
        assertEquals(fileReadOrder.next(), second);
        assertEquals(fileReadOrder.next(), third);
        assertEquals(fileReadOrder.next(), fourth);
        assertFalse(fileReadOrder.hasNext());
    }

    @Test
    void addShouldNotReplaceExistingIsoOid() throws IOException {
        final OID isoOid = new OID("1");

        when(oidTrie.find(isoOid))
                .thenReturn(Optional.of(new OidData("node", "iso", "EXISTING")));

        final Path dicPath = Resources.path("mib-manager-test/DIC-MIB.dic");

        mibManager.add(dicPath.toString());

        verify(oidTrie, never()).insert(any(OID.class), any());
    }

    @Test
    void mapShouldFormatEventFieldsUsingCorrectArguments() {
        final OID oid = new OID("1.5.3");
        final OidData expectedOidData = new OidData("node", "value" + oid.last(), "FOO");

        when(oidTrie.find(eq(oid), ArgumentMatchers.any()))
                .thenAnswer(m -> {
                    try {
                        final Consumer<OidTrie.OidTrieNode> edgesConsumer = m.getArgument(1);
                        for (final int id : oid.getValue()) {
                            final OidTrie.OidTrieNode node = new OidTrie.OidTrieNode(id);
                            node.setData(new OidData("node", "value" + id, "FOO"));
                            edgesConsumer.accept(node);
                        }
                        return Optional.of(expectedOidData);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });


        mibManager.map(oid);

        verify(oidFieldMapper)
                .map(eq(oid), argThat(p->
                        "value1".equals(p[0].getData().getName()) &&
                        "value5".equals(p[1].getData().getName()) &&
                        "value3".equals(p[2].getData().getName())));
    }

    @Test
    void shouldUseDefaultFileReaders() {
        final MibManager manager = new MibManager();

        final MibReader dic = manager.getMibFileReaders().get("dic");
        assertNotNull(dic);
        assertInstanceOf(SmilibPythonMibReader.class, dic);

        final MibReader yaml = manager.getMibFileReaders().get("yaml");
        assertNotNull(yaml);
        assertInstanceOf(RubySnmpMibReader.class, yaml);
    }
}