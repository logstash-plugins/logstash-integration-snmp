package org.logstash.snmp;

import org.logstash.snmp.mib.MibManager;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.OctetString;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.logstash.snmp.SnmpUtils.parseAuthProtocol;
import static org.logstash.snmp.SnmpUtils.parseNullableOctetString;
import static org.logstash.snmp.SnmpUtils.parsePrivProtocol;
import static org.logstash.snmp.SnmpUtils.parseSecurityLevel;

public final class SnmpClientBuilder {
    private static final Pattern COLON_DELIMITED_HEX_BYTES = Pattern.compile("^(?i:[0-9a-f]{2}(?::[0-9a-f]{2})+)$");

    private final MibManager mib;
    private final int port;
    private OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
    private final Set<String> supportedTransports;
    private Set<Integer> supportedVersions = Set.of(SnmpConstants.version1, SnmpConstants.version2c, SnmpConstants.version3);
    private String host = "0.0.0.0";
    private final List<User> usmUsers = new ArrayList<>();
    private int messageDispatcherPoolSize = 1;
    private String messageDispatcherPoolName = "SnmpMessageDispatcherWorker";
    private Duration closeTimeoutDuration;
    private boolean mapOidVariableValues = false;
    private String engineBootsPersistencePath;
    private boolean localEngineIdConfigured;

    public SnmpClientBuilder(MibManager mib, Set<String> supportedTransports, int port) {
        this.mib = mib;
        this.supportedTransports = supportedTransports;
        this.port = port;
    }

    public SnmpClientBuilder setHost(final String host) {
        this.host = host;
        return this;
    }

    public SnmpClientBuilder setLocalEngineId(final String localEngineId) {
        if (COLON_DELIMITED_HEX_BYTES.matcher(localEngineId).matches()) {
            this.localEngineId = OctetString.fromHexString(localEngineId, ':');
        } else {
            this.localEngineId = new OctetString(localEngineId);
        }
        this.localEngineIdConfigured = true;
        return this;
    }

    public SnmpClientBuilder setLocalEngineId(final byte[] localEngineId) {
        this.localEngineId = new OctetString(localEngineId);
        this.localEngineIdConfigured = true;
        return this;
    }

    public SnmpClientBuilder addUsmUser(
            String securityName,
            String authProtocol,
            String authPassphrase,
            String privProtocol,
            String privPassphrase,
            String securityLevel
    ) {
        final UsmUser usmUser = new UsmUser(
                new OctetString(securityName),
                parseAuthProtocol(authProtocol),
                parseNullableOctetString(authPassphrase),
                parsePrivProtocol(privProtocol),
                parseNullableOctetString(privPassphrase)
        );
        this.usmUsers.add(new User(usmUser, parseSecurityLevel(securityLevel)));
        return this;
    }

    public SnmpClientBuilder setMessageDispatcherPoolName(final String messageDispatcherPoolName) {
        this.messageDispatcherPoolName = messageDispatcherPoolName;
        return this;
    }

    public SnmpClientBuilder setMessageDispatcherPoolSize(final int messageDispatcherPoolSize) {
        this.messageDispatcherPoolSize = Math.max(1, messageDispatcherPoolSize);
        return this;
    }

    public SnmpClientBuilder setSupportedVersions(final Set<String> supportedVersions) {
        final Set<Integer> versions = supportedVersions
                .stream()
                .map(SnmpUtils::parseSnmpVersion)
                .collect(Collectors.toCollection(HashSet::new));

        if (versions.isEmpty()) {
            throw new IllegalArgumentException("at least one SNMP version must be supported");
        }

        this.supportedVersions = versions;
        return this;
    }

    SnmpClientBuilder setCloseTimeoutDuration(final Duration closeTimeoutDuration) {
        this.closeTimeoutDuration = closeTimeoutDuration;
        return this;
    }

    public SnmpClientBuilder setMapOidVariableValues(final boolean mapOidVariableValues) {
        this.mapOidVariableValues = mapOidVariableValues;
        return this;
    }

    public SnmpClientBuilder setEngineBootsPersistencePath(final String engineBootsPersistencePath) {
        this.engineBootsPersistencePath = engineBootsPersistencePath;
        return this;
    }

    public SnmpClient build() throws IOException {
        if (!localEngineIdConfigured) {
            localEngineId = EngineBootsStore.resolveLocalEngineId(engineBootsPersistencePath, localEngineId);
        }

        final SnmpClient client = new SnmpClient(
                mib,
                supportedTransports,
                supportedVersions,
                host,
                port,
                messageDispatcherPoolName,
                messageDispatcherPoolSize,
                usmUsers,
                localEngineId,
                engineBootsPersistencePath,
                mapOidVariableValues
        );

        if (closeTimeoutDuration != null) {
            client.setCloseTimeoutDuration(closeTimeoutDuration);
        }

        return client;
    }
}
