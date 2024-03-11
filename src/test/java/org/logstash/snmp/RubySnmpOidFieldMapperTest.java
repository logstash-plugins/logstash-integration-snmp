package org.logstash.snmp;

import org.junit.jupiter.api.Test;
import org.logstash.snmp.mib.OidData;
import org.snmp4j.smi.OID;

import static java.util.Objects.nonNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.logstash.snmp.OidFieldMapper.ResolvedIdentifier;

class RubySnmpOidFieldMapperTest {
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
        final RubySnmpOidFieldMapper mapper = new RubySnmpOidFieldMapper();

        final String result = mapper.map(AN_OID, OID_RESOLVED_QUALIFIERS);

        assertEquals("FOO::sysDescr", result);
    }

    @Test
    void shouldMapAsDottedStringWhenResolvedIdentifiersIsEmpty() {
        final RubySnmpOidFieldMapper mapper = new RubySnmpOidFieldMapper();

        final String result = mapper.map(AN_OID, new ResolvedIdentifier[0]);

        assertEquals(AN_OID.toDottedString(), result);
    }

    @Test
    void shouldMapAsDottedStringWhenLastResolvedIdentifierHasNoData() {
        final RubySnmpOidFieldMapper mapper = new RubySnmpOidFieldMapper();

        final String result = mapper.map(new OID("1.2"), new ResolvedIdentifier[]{
                resolvedIdentifier(1, "iso"),
                resolvedIdentifier(2, null)
        });

        assertEquals("1.2", result);
    }

    @Test
    void shouldMapPartiallyResolvedIdentifiers() {
        final RubySnmpOidFieldMapper mapper = new RubySnmpOidFieldMapper();

        final String result = mapper.map(new OID(AN_OID).append(1).append(2), OID_RESOLVED_QUALIFIERS);

        assertEquals("FOO::sysDescr.1.2", result);
    }

    private static ResolvedIdentifier resolvedIdentifier(int identifier, String name) {
        final OidData data = nonNull(name) ? new OidData("node", name, A_MODULE_NAME) : null;
        return new ResolvedIdentifier(identifier, data);
    }
}