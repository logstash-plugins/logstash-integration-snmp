package org.logstash.snmp;

import org.snmp4j.smi.OID;

public class RubySnmpOidFieldMapper implements OidFieldMapper {
    @Override
    public String map(final OID oid, final ResolvedIdentifier[] resolvedOidIdentifiers) {
        if (resolvedOidIdentifiers == null || resolvedOidIdentifiers.length == 0) {
            return oid.toDottedString();
        }

        final ResolvedIdentifier lastResolvedIdentifier = resolvedOidIdentifiers[resolvedOidIdentifiers.length - 1];
        if (lastResolvedIdentifier.getData() == null) {
            return oid.toDottedString();
        }

        final StringBuilder mappedIdentifier = new StringBuilder();
        final String moduleName = lastResolvedIdentifier.getData().getModuleName();
        if (moduleName != null && !moduleName.isEmpty()) {
            mappedIdentifier.append(moduleName);
            mappedIdentifier.append("::");
        }

        mappedIdentifier.append(lastResolvedIdentifier.getData().getName());

        int unresolvedIdentifiers = oid.size() - resolvedOidIdentifiers.length;
        while (unresolvedIdentifiers > 0) {
            mappedIdentifier.append(".");
            mappedIdentifier.append(oid.get(oid.size() - unresolvedIdentifiers));
            unresolvedIdentifiers--;
        }

        return mappedIdentifier.toString();
    }
}
