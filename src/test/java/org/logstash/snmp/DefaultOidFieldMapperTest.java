package org.logstash.snmp;

import org.junit.jupiter.api.Test;
import org.logstash.snmp.mib.OidData;
import org.snmp4j.smi.OID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;


class DefaultOidFieldMapperTest {
    private final OID AN_OID = new OID("1.3.6.1.2.1.1.1");
    private final String[] OID_RESOLVED_QUALIFIERS = {"iso", "org", "dod", "internet", "mgmt", "mib-2", "system", "sysDescr"};
    private final OidData OID_DATA = new OidData("node", "sysDescr", "DUMMY");
    private static final OidData NO_DATA = null;

    @Test
    void shouldMapFullyResolvedIdentifiers() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper();

        final String result = mapper.map(AN_OID, OID_RESOLVED_QUALIFIERS, OID_DATA);

        assertEquals("iso.org.dod.internet.mgmt.mib-2.system.sysDescr", result);
    }

    @Test
    void shouldMapPartiallyResolvedIdentifiers() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper();

        final String result = mapper.map(new OID(AN_OID).append(3), OID_RESOLVED_QUALIFIERS, NO_DATA);

        assertEquals("iso.org.dod.internet.mgmt.mib-2.system.sysDescr.3", result);
    }

    @Test
    void shouldSkipRootIdentifiers() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper(2, 0);

        final String result = mapper.map(AN_OID, OID_RESOLVED_QUALIFIERS, OID_DATA);

        assertEquals("dod.internet.mgmt.mib-2.system.sysDescr", result);
    }

    @Test
    void shouldMapEmptyWhenOidSkipRootIsBiggerThanOidSize() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper(100, 0);

        final String result = mapper.map(AN_OID, OID_RESOLVED_QUALIFIERS, OID_DATA);

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

        final String result = mapper.map(AN_OID, OID_RESOLVED_QUALIFIERS, OID_DATA);

        assertEquals("sysDescr", result);
    }

    @Test
    void shouldMapPartiallyResolvedIdentifiersWithPathLength() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper(0, 3);

        final String result = mapper.map(new OID(AN_OID).append(5), OID_RESOLVED_QUALIFIERS, NO_DATA);

        assertEquals("system.sysDescr.5", result);
    }

    @Test
    void shouldMapAllIdentifiersWhenPathLengthIsBiggerThanOidSize() {
        final DefaultOidFieldMapper mapper = new DefaultOidFieldMapper(0, 100);

        final String result = mapper.map(new OID(AN_OID).append(8), OID_RESOLVED_QUALIFIERS, NO_DATA);

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

        assertEquals("Specify either an oidRootSkip and oidPathLength", exception.getMessage());
    }
}