package org.logstash.snmp;

import org.junit.jupiter.api.Test;
import org.logstash.snmp.mib.OidData;
import org.snmp4j.smi.OID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DottedStringOidFieldMapperTest {

    private static final OID AN_OID = new OID("1.3.6.1.2.1.1.1");
    private static final String A_MODULE_NAME = "FOO";
    private static final OidFieldMapper.ResolvedIdentifier[] OID_RESOLVED_IDENTIFIERS = {
            resolvedIdentifier(1, "iso"),
            resolvedIdentifier(3, "org"),
            resolvedIdentifier(6, "dod"),
            resolvedIdentifier(1, "internet"),
            resolvedIdentifier(2, "mgmt"),
            resolvedIdentifier(1, "mib-2"),
            resolvedIdentifier(1, "system"),
            resolvedIdentifier(1, "sysDescr"),
    };

    private static OidFieldMapper.ResolvedIdentifier resolvedIdentifier(int identifier, String name) {
        return new OidFieldMapper.ResolvedIdentifier(identifier, new OidData("node", name, A_MODULE_NAME));
    }

    @Test
    void shouldMapAsDottedStringWhenNoIdentifierIsResolved() {
        final DottedStringOidFieldMapper mapper = new DottedStringOidFieldMapper();

        final String result = mapper.map(AN_OID, new OidFieldMapper.ResolvedIdentifier[0]);

        assertEquals(AN_OID.toDottedString(), result);
    }

    @Test
    void shouldMapAsDottedStringWhenAllIdentifiersAreResolved() {
        final DottedStringOidFieldMapper mapper = new DottedStringOidFieldMapper();

        final String result = mapper.map(AN_OID, OID_RESOLVED_IDENTIFIERS);

        assertEquals(AN_OID.toDottedString(), result);
    }

    @Test
    void shouldMapAsDottedStringWhenIdentifiersArePartiallyResolved() {
        final DottedStringOidFieldMapper mapper = new DottedStringOidFieldMapper();

        final OID oid = AN_OID.append(1).append(5);
        final String result = mapper.map(oid, OID_RESOLVED_IDENTIFIERS);

        assertEquals(oid.toDottedString(), result);
    }
}