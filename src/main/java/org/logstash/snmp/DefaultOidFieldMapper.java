package org.logstash.snmp;

import org.snmp4j.smi.OID;

import java.util.Arrays;
import java.util.stream.Collectors;

public class DefaultOidFieldMapper implements OidFieldMapper {
    private final int oidRootSkip;
    private final int oidPathLength;

    public DefaultOidFieldMapper() {
        this(0, 0);
    }

    public DefaultOidFieldMapper(int oidRootSkip, int oidPathLength) {
        if (oidRootSkip != 0 && oidPathLength != 0) {
            throw new IllegalArgumentException("Specify either an oidRootSkip or oidPathLength");
        }

        if (oidRootSkip < 0) {
            throw new IllegalArgumentException("oidRootSkip must be positive number");
        }

        if (oidPathLength < 0) {
            throw new IllegalArgumentException("oidPathLength must be positive number");
        }

        this.oidRootSkip = oidRootSkip;
        this.oidPathLength = oidPathLength;
    }

    @Override
    public String map(OID oid, final ResolvedIdentifier[] resolvedOidIdentifiers) {
        final int[] identifiers = oid.getValue();
        final String[] mappedIdentifiers;

        if (identifiers.length == resolvedOidIdentifiers.length) {
            mappedIdentifiers = Arrays.stream(resolvedOidIdentifiers)
                    .map(this::getNameOrIdentifier)
                    .toArray(String[]::new);
        } else {
            mappedIdentifiers = mapPartiallyQualifiedOid(oid, resolvedOidIdentifiers);
        }

        if (oidRootSkip > 0) {
            return Arrays.stream(mappedIdentifiers)
                    .skip(oidRootSkip)
                    .collect(Collectors.joining("."));
        }

        if (oidPathLength > 0 && oidPathLength < mappedIdentifiers.length) {
            return Arrays.stream(mappedIdentifiers)
                    .skip((long) mappedIdentifiers.length - oidPathLength)
                    .collect(Collectors.joining("."));
        }

        return String.join(".", mappedIdentifiers);
    }

    private String[] mapPartiallyQualifiedOid(OID oid, final ResolvedIdentifier[] resolvedOidIdentifiers) {
        final String[] mappedIdentifiers = new String[oid.size()];
        final int resolvedOidUpperBound = resolvedOidIdentifiers.length - 1;

        for (int i = 0; i < oid.getValue().length; i++) {
            if (i > resolvedOidUpperBound) {
                mappedIdentifiers[i] = String.valueOf(oid.get(i));
            } else {
                mappedIdentifiers[i] = getNameOrIdentifier(resolvedOidIdentifiers[i]);
            }
        }

        return mappedIdentifiers;
    }

    private String getNameOrIdentifier(ResolvedIdentifier resolvedIdentifier) {
        if (resolvedIdentifier.getData() != null) {
            return resolvedIdentifier.getData().getName();
        }

        return String.valueOf(resolvedIdentifier.getIdentifier());
    }
}
