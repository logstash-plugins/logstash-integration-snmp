package org.logstash.snmp;

import org.logstash.snmp.mib.OidData;
import org.snmp4j.smi.OID;

public interface OidFieldMapper {

    String map(OID oid, ResolvedIdentifier[] resolvedOidIdentifiers);

    class ResolvedIdentifier {
        private final int identifier;
        private final OidData data;

        public ResolvedIdentifier(int identifier, OidData data) {
            this.identifier = identifier;
            this.data = data;
        }

        public int getIdentifier() {
            return identifier;
        }

        public OidData getData() {
            return data;
        }

        @Override
        public String toString() {
            return "ResolvedIdentifier{" +
                    "identifier=" + identifier +
                    ", data=" + data +
                    '}';
        }
    }
}
