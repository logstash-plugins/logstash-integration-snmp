package org.logstash.snmp;

import org.junit.jupiter.api.Test;
import org.logstash.snmp.mib.OidData;
import org.snmp4j.smi.OID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.logstash.snmp.OidFieldMapper.ResolvedIdentifier;


class DefaultOidFieldMapperTest {
    private static final OID AN_OID = new OID("1.3.6.1.2.1.1.1");
    private static final String A_MODULE_NAME = "FOO";
    private static final ResolvedIdentifier[] OID_RESOLVED_QUALIFIERS = {
            resolvedIdentifier(1, "iso"),
            resolvedIdentifier(3, "org"),
            resolvedIdentifier(6, "dod"),
            resolvedIdentifier(1, "internet"),
            resolvedIdentifier(2, "mgmt"),
            resolvedIdentifier(1, "mib-2"),
            resolvedIdentifier(1, "system"),
            resolvedIdentifier(1, "sysDescr"),
    };

    @Test
    void shouldMapFullyResolvedIdentifiers() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper();

        final String result = mapper.map(AN_OID, OID_RESOLVED_QUALIFIERS);

        assertEquals("iso.org.dod.internet.mgmt.mib-2.system.sysDescr", result);
    }

    @Test
    void shouldMapPartiallyResolvedIdentifiers() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper();

        final String result = mapper.map(new OID(AN_OID).append(3), OID_RESOLVED_QUALIFIERS);

        assertEquals("iso.org.dod.internet.mgmt.mib-2.system.sysDescr.3", result);
    }

    @Test
    void shouldSkipRootIdentifiers() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper(2, 0);

        final String result = mapper.map(AN_OID, OID_RESOLVED_QUALIFIERS);

        assertEquals("dod.internet.mgmt.mib-2.system.sysDescr", result);
    }

    @Test
    void shouldMapEmptyWhenOidSkipRootIsBiggerThanOidSize() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper(100, 0);

        final String result = mapper.map(AN_OID, OID_RESOLVED_QUALIFIERS);

        assertEquals("", result);
    }

    @Test
    void shouldThrowWhenOidSkipRootIsNegative() {
        final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> new DefaultOidFieldMapper(-1, 0)
        );

        assertEquals("oidRootSkip must be positive number", exception.getMessage());
    }

    @Test
    void shouldMapFullyResolvedIdentifiersWithPathLength() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper(0, 1);

        final String result = mapper.map(AN_OID, OID_RESOLVED_QUALIFIERS);

        assertEquals("sysDescr", result);
    }

    @Test
    void shouldMapPartiallyResolvedIdentifiersWithPathLength() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper(0, 3);

        final String result = mapper.map(new OID(AN_OID).append(5), OID_RESOLVED_QUALIFIERS);

        assertEquals("system.sysDescr.5", result);
    }

    @Test
    void shouldMapAllIdentifiersWhenPathLengthIsBiggerThanOidSize() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper(0, 100);

        final String result = mapper.map(new OID(AN_OID).append(8), OID_RESOLVED_QUALIFIERS);

        assertEquals("iso.org.dod.internet.mgmt.mib-2.system.sysDescr.8", result);
    }

    @Test
    void shouldThrowWhenOidPathLengthIsNegative() {
        final IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> new DefaultOidFieldMapper(0, -1));

        assertEquals("oidPathLength must be positive number", exception.getMessage());
    }

    @Test
    void shouldThrowWhenOidSkipRootAndPathLengthAreSpecified() {
        final IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> new DefaultOidFieldMapper(1, 1));

        assertEquals("Specify either an oidRootSkip or oidPathLength", exception.getMessage());
    }

    private static ResolvedIdentifier resolvedIdentifier(int identifier, String name){
        return new ResolvedIdentifier(identifier, new OidData("node", name, A_MODULE_NAME));
    }
}