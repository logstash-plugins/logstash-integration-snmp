package org.logstash.snmp;

import org.snmp4j.smi.OID;

public class DottedStringOidFieldMapper implements OidFieldMapper {
    @Override
    public String map(final OID oid, final ResolvedIdentifier[] ignore) {
        return oid.toDottedString();
    }
}
