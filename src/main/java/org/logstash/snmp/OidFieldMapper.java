package org.logstash.snmp;

import org.logstash.snmp.mib.OidData;
import org.snmp4j.smi.OID;

public interface OidFieldMapper {
    String map(OID oid, String[] resolvedOidIdentifiers, OidData data);
}
