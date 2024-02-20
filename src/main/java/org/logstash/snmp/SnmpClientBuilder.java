package org.logstash.snmp;

import org.logstash.snmp.mib.MibManager;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.OctetString;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.logstash.snmp.SnmpUtils.parseAuthProtocol;
import static org.logstash.snmp.SnmpUtils.parseNullableOctetString;
import static org.logstash.snmp.SnmpUtils.parsePrivProtocol;

public final class SnmpClientBuilder {
    private final MibManager mib;
    private final int port;
    private OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
    private final Set<String> protocols;
    private String host = "0.0.0.0";
    private final List<UsmUser> usmUsers = new ArrayList<>();
    private int threadPoolSize = 1;
    private String threadPoolName = "SnmpWorker";
    private OctetString contextEngineId;
    private OctetString contextName;

    public SnmpClientBuilder(MibManager mib, Set<String> protocols, int port) {
        this.mib = mib;
        this.protocols = protocols;
        this.port = port;
    }

    public SnmpClientBuilder addProtocol(final String protocol) {
        this.protocols.add(protocol);
        return this;
    }

    public SnmpClientBuilder setHost(final String host) {
        this.host = host;
        return this;
    }

    public SnmpClientBuilder setLocalEngineId(final String localEngineId) {
        this.localEngineId = new OctetString(localEngineId);
        return this;
    }

    public SnmpClientBuilder addUsmUser(
            String securityName,
            String authProtocol,
            String authPassphrase,
            String privProtocol,
            String privPassphrase
    ) {
        this.usmUsers.add(new UsmUser(
                new OctetString(securityName),
                parseAuthProtocol(authProtocol),
                parseNullableOctetString(authPassphrase),
                parsePrivProtocol(privProtocol),
                parseNullableOctetString(privPassphrase)
        ));

        return this;
    }

    public SnmpClientBuilder setThreadPoolName(final String threadPoolName) {
        this.threadPoolName = threadPoolName;
        return this;
    }

    public SnmpClientBuilder setThreadPoolSize(final int threadPoolSize) {
        this.threadPoolSize = Math.max(1, threadPoolSize);
        return this;
    }

    public SnmpClientBuilder setContextEngineId(final String contextEngineId) {
        this.contextEngineId = new OctetString(contextEngineId);
        return this;
    }

    public SnmpClientBuilder setContextName(final String contextName) {
        this.contextName = new OctetString(contextName);
        return this;
    }

    public SnmpClient build() throws IOException {
        return new SnmpClient(
                mib,
                protocols,
                host,
                port,
                threadPoolName,
                threadPoolSize,
                usmUsers,
                localEngineId,
                contextEngineId,
                contextName
        );
    }
}
