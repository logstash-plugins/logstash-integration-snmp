package org.logstash.snmp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.logstash.snmp.mib.MibManager;
import org.logstash.snmp.trap.SnmpTrapMessage;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.AuthenticationFailureEvent;
import org.snmp4j.event.AuthenticationFailureListener;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.log.Log4jLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.SecurityProtocols.SecurityProtocolSet;
import org.snmp4j.security.TSM;
import org.snmp4j.security.USM;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.AssignableFromInteger;
import org.snmp4j.smi.AssignableFromLong;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.SMIConstants;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.TlsAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.transport.TLSTM;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.PDUFactory;
import org.snmp4j.util.TableEvent;
import org.snmp4j.util.TableUtils;
import org.snmp4j.util.ThreadPool;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import static java.util.Objects.nonNull;
import static org.logstash.snmp.SnmpUtils.parseSecurityLevel;
import static org.logstash.snmp.SnmpUtils.parseSnmpVersion;

public class SnmpClient implements Closeable {
    private static final Logger logger = LogManager.getLogger(SnmpClient.class);

    private final MibManager mib;
    private final Snmp snmp;
    private final Set<String> supportedTransports;
    private final Set<Integer> supportedVersions;
    private final CountDownLatch stopCountDownLatch = new CountDownLatch(1);
    private Duration closeTimeoutDuration = Duration.ofMinutes(1);
    private final String host;
    private final int port;
    private final boolean mapOidVariableValues;
    private final Map<OctetString, Integer> usmUsersSecurityLevel = new HashMap<>();

    static {
        LogFactory.setLogFactory(new Log4jLogFactory());
    }

    public static SnmpClientBuilder builder(MibManager mib, Set<String> protocols) {
        return new SnmpClientBuilder(mib, protocols, 0);
    }

    public static SnmpClientBuilder builder(MibManager mib, Set<String> protocols, int port) {
        return new SnmpClientBuilder(mib, protocols, port);
    }

    SnmpClient(
            MibManager mib,
            Set<String> supportedTransports,
            Set<Integer> supportedVersions,
            String host,
            int port,
            String messageDispatcherPoolName,
            int messageDispatcherPoolSize,
            List<User> users,
            OctetString localEngineId,
            boolean mapOidVariableValues
    ) throws IOException {
        this.mib = mib;
        this.host = host;
        this.port = port;
        this.supportedVersions = supportedVersions;
        this.supportedTransports = supportedTransports;
        this.mapOidVariableValues = mapOidVariableValues;
        users.forEach(p -> this.usmUsersSecurityLevel.put(p.getSecurityName(), p.getSecurityLevel()));

        // global security models/protocols
        SecurityProtocols.getInstance().addPredefinedProtocolSet(SecurityProtocolSet.maxCompatibility);
        SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

        if (supportedVersions.contains(SnmpConstants.version3)) {
            SecurityModels.getInstance().addSecurityModel(new TSM(localEngineId, false));
        }

        this.snmp = createSnmpClient(
                supportedTransports,
                supportedVersions,
                host,
                port,
                localEngineId,
                users,
                messageDispatcherPoolName,
                messageDispatcherPoolSize
        );
    }

    private static Snmp createSnmpClient(
            Set<String> supportedTransports,
            Set<Integer> supportedVersions,
            String host,
            int port,
            OctetString localEngineId,
            List<User> users,
            String messageDispatcherPoolName,
            int messageDispatcherPoolSize
    ) throws IOException {
        final int engineBootCount = 0;
        final MessageDispatcher messageDispatcher = createMessageDispatcher(
                localEngineId,
                supportedVersions,
                users,
                engineBootCount,
                messageDispatcherPoolName,
                messageDispatcherPoolSize
        );

        final Snmp snmp = new Snmp(messageDispatcher);
        for (final String transport : supportedTransports) {
            snmp.addTransportMapping(createTransport(parseAddress(transport, host, port)));
        }

        return snmp;
    }

    private static MessageDispatcher createMessageDispatcher(
            OctetString localEngineId,
            Set<Integer> supportedVersions,
            List<User> users,
            int engineBootCount,
            String messageDispatcherPoolName,
            int messageDispatcherPoolSize
    ) {
        final ThreadPool threadPool = ThreadPool.create(messageDispatcherPoolName, messageDispatcherPoolSize);
        final MessageDispatcherImpl dispatcherImpl = new MessageDispatcherImpl();
        final MessageDispatcher dispatcher = new MultiThreadedMessageDispatcher(threadPool, dispatcherImpl);

        if (supportedVersions.contains(SnmpConstants.version1)) {
            dispatcher.addMessageProcessingModel(new MPv1());
        }

        if (supportedVersions.contains(SnmpConstants.version2c)) {
            dispatcher.addMessageProcessingModel(new MPv2c());
        }

        if (supportedVersions.contains(SnmpConstants.version3)) {
            final MPv3 mpv3 = new MPv3(createUsm(users, localEngineId, engineBootCount));
            mpv3.setCurrentMsgID(MPv3.randomMsgID(engineBootCount));
            dispatcher.addMessageProcessingModel(mpv3);

            // When enabled, it logs authentication failures from incoming messages
            if (logger.isDebugEnabled()) {
                dispatcherImpl.addAuthenticationFailureListener(new AuthenticationFailureListener() {
                    @Override
                    public <A extends Address> void authenticationFailure(final AuthenticationFailureEvent<A> event) {
                        final String message = SnmpConstants.usmErrorMessage(event.getError());
                        logger.debug("SNMP authentication failed. source: {}, reason: {} ({})",
                                event.getAddress(),
                                message,
                                event.getError());

                    }
                });
            }
        }

        return dispatcher;
    }

    private static USM createUsm(List<User> users, OctetString localEngineID, int engineBootCount) {
        final USM usm = new USM(SecurityProtocols.getInstance(), localEngineID, engineBootCount);

        if (users != null) {
            users.stream().map(User::getUsmUser).forEach(usm::addUser);
        }

        return usm;
    }

    public void listen() throws IOException {
        getSnmp().listen();
    }

    public void trap(String[] allowedSecurityNames, Consumer<SnmpTrapMessage> consumer) throws IOException {
        doTrap(allowedSecurityNames, consumer, stopCountDownLatch);
    }

    void doTrap(String[] communities, Consumer<SnmpTrapMessage> consumer, CountDownLatch stopCountDownLatch) throws IOException {
        final Set<String> allowedCommunities = Set.of(communities);
        getSnmp().addCommandResponder(new CommandResponder() {
            @Override
            public <A extends Address> void processPdu(final CommandResponderEvent<A> event) {
                logger.debug("SNMP Trap received: {}", event);
                final int version = event.getMessageProcessingModel();
                final String securityName = new String(event.getSecurityName());
                if (!validateTrapMessage(version, securityName, event.getSecurityLevel(), allowedCommunities)) {
                    return;
                }

                final Map<String, Object> trapEvent = createTrapEvent(version, securityName, event.getPDU());
                final Map<String, Object> formattedVarBindings = new HashMap<>(event.getPDU().getVariableBindings().size());
                for (VariableBinding binding : event.getPDU().getVariableBindings()) {
                    formattedVarBindings.put(mib.map(binding.getOid()), coerceVariable(binding.getVariable()));
                }

                final SnmpTrapMessage trapMessage = new SnmpTrapMessage(
                        version,
                        event.getSecurityName(),
                        event.getPeerAddress(),
                        trapEvent,
                        formattedVarBindings);

                consumer.accept(trapMessage);
            }
        });

        getSnmp().listen();

        if (logger.isInfoEnabled()) {
            final String[] versions = supportedVersions.stream().map(SnmpUtils::parseSnmpVersion).toArray(String[]::new);
            logger.info("SNMP trap receiver started on host: {}, port: {}, transports: {}, versions: {}.", host, port, supportedTransports, versions);
        }

        try {
            stopCountDownLatch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private boolean validateTrapMessage(int version, String securityName, int securityLevel, Set<String> allowedCommunities) {
        if (version < SnmpConstants.version3) {
            // Empty communities means "allow all communities" (BC with ruby-snmp)
            if (!allowedCommunities.isEmpty() && !allowedCommunities.contains(securityName)) {
                logger.debug("Received trap message with unknown community: '{}'. Skipping", securityName);
                return false;
            }
        } else {
            final int userSecurityLevel = this.usmUsersSecurityLevel.get(OctetString.fromString(securityName));
            if (securityLevel < userSecurityLevel) {
                logger.debug("Unsupported security level {} by user {}, minimum security level is {}. Skipping", SecurityLevel.get(securityLevel), securityName, SecurityLevel.get(userSecurityLevel));
                return false;
            }
        }
        return true;
    }

    private Map<String, Object> createTrapEvent(int version, final String securityName, PDU pdu) {
        final HashMap<String, Object> trapEvent = new HashMap<>();
        trapEvent.put("version", SnmpUtils.parseSnmpVersion(version));
        trapEvent.put("type", PDU.getTypeString(pdu.getType()));

        if (version > SnmpConstants.version1) {
            final int requestId = nonNull(pdu.getRequestID()) ? pdu.getRequestID().getValue() : 0;
            trapEvent.put("request_id", requestId);
            trapEvent.put("error_status", pdu.getErrorStatus());
            trapEvent.put("error_status_text", pdu.getErrorStatusText());
            trapEvent.put("error_index", pdu.getErrorIndex());
        } else if (pdu instanceof PDUv1) {
            final PDUv1 pdUv1 = (PDUv1) pdu;
            trapEvent.put("enterprise", String.valueOf(pdUv1.getEnterprise()));
            trapEvent.put("agent_addr", String.valueOf(pdUv1.getAgentAddress()));
            trapEvent.put("generic_trap", pdUv1.getGenericTrap());
            trapEvent.put("specific_trap", pdUv1.getSpecificTrap());
            trapEvent.put("timestamp", pdUv1.getTimestamp());
        }

        if (version < SnmpConstants.version3) {
            trapEvent.put("community", securityName);
        }

        final Map<String, Object> coercedVarBindings = new HashMap<>(pdu.getVariableBindings().size());
        for (VariableBinding binding : pdu.getVariableBindings()) {
            coercedVarBindings.put(binding.getOid().toString(), coerceVariable(binding.getVariable()));
        }

        trapEvent.put("variable_bindings", coercedVarBindings);

        return trapEvent;
    }

    public Map<String, Object> get(Target<Address> target, OID[] oids) throws IOException {
        validateTargetVersion(target);

        final PDU pdu = createPDU(target, PDU.GET);
        pdu.addAll(VariableBinding.createFromOIDs(oids));

        final ResponseEvent<Address> responseEvent = getSnmp().send(pdu, target);
        if (responseEvent == null) {
            return Collections.emptyMap();
        }

        final Exception error = responseEvent.getError();
        if (error != null) {
            throw new SnmpClientException(
                    String.format("error sending snmp get request to target %s: %s", target.getAddress(), error.getMessage()),
                    error
            );
        }

        final PDU responsePdu = responseEvent.getResponse();
        if (responsePdu == null) {
            throw new SnmpClientException(String.format("timeout sending snmp get request to target %s", target.getAddress()));
        }

        final Map<String, Object> result = new HashMap<>();
        for (VariableBinding binding : responsePdu.getVariableBindings()) {
            final String oid = mib.map(binding.getOid());
            result.put(oid, coerceVariable(binding.getVariable()));
        }

        return result;
    }

    public Map<String, Object> walk(Target<Address> target, OID oid) {
        validateTargetVersion(target);

        final TreeUtils treeUtils = createGetTreeUtils();
        final List<TreeEvent> events = treeUtils.getSubtree(target, oid);

        if (events == null || events.isEmpty()) {
            return Collections.emptyMap();
        }

        final Map<String, Object> result = new HashMap<>();
        for (final TreeEvent event : events) {
            if (event == null) {
                continue;
            }

            if (event.isError()) {
                throw new SnmpClientException(
                        String.format("error sending snmp walk request to target %s: %s", target.getAddress(), event.getErrorMessage()),
                        event.getException()
                );
            }

            final VariableBinding[] variableBindings = event.getVariableBindings();
            if (variableBindings == null) {
                continue;
            }

            for (final VariableBinding variableBinding : variableBindings) {
                if (variableBinding == null) {
                    continue;
                }

                result.put(
                        mib.map(variableBinding.getOid()),
                        coerceVariable(variableBinding.getVariable())
                );
            }
        }

        return result;
    }

    TreeUtils createGetTreeUtils() {
        return new TreeUtils(getSnmp(), creatPDUFactory(PDU.GET));
    }

    public Map<String, List<Map<String, Object>>> table(Target<Address> target, String tableName, OID[] oids) {
        validateTargetVersion(target);

        final TableUtils tableUtils = createGetTableUtils();
        final List<TableEvent> events = tableUtils.getTable(target, oids, null, null);

        if (events == null || events.isEmpty()) {
            return Collections.emptyMap();
        }

        final List<Map<String, Object>> rows = new ArrayList<>(events.size());
        for (final TableEvent event : events) {
            if (event == null) {
                continue;
            }

            if (event.isError()) {
                throw new SnmpClientException(
                        String.format("error sending snmp table request to target %s: %s", target.getAddress(), event.getErrorMessage()),
                        event.getException()
                );
            }

            final VariableBinding[] variableBindings = event.getColumns();
            if (variableBindings == null || variableBindings.length == 0) {
                continue;
            }

            final Map<String, Object> row = new HashMap<>();
            row.put("index", String.valueOf(event.getIndex()));

            for (final VariableBinding binding : variableBindings) {
                if (binding == null) {
                    continue;
                }

                final String mappedOid = mib.map(removeVariableOidIndex(binding.getOid(), event.getIndex()));
                final Object value = coerceVariable(binding.getVariable());
                row.put(mappedOid, value);
            }

            rows.add(row);
        }

        return Collections.singletonMap(tableName, rows);
    }

    // The org.snmp4j.util.TableEvent columns OIDs contains the table's index value appended to
    // its rightmost sub-identifiers. There's no reason to maintain that value as this plugin
    // separate each table's event per row/object, and adds the index value to a specific "index"
    // field, avoiding repetition on the field names and keeping it backward compatible.
    private OID removeVariableOidIndex(OID oid, OID eventIndex) {
        if (oid.rightMostCompare(eventIndex.size(), eventIndex) != 0) {
            return oid;
        }

        return oid.subOID(0, oid.size() - eventIndex.size());
    }

    TableUtils createGetTableUtils() {
        return new TableUtils(getSnmp(), creatPDUFactory(PDU.GET));
    }

    Object coerceVariable(Variable variable) {
        if (variable.isException()) {
            switch (variable.getSyntax()) {
                case SMIConstants.EXCEPTION_NO_SUCH_INSTANCE:
                    return "error: no such instance currently exists at this OID";
                case SMIConstants.EXCEPTION_NO_SUCH_OBJECT:
                    return "error: no such object currently exists at this OID";
                case SMIConstants.EXCEPTION_END_OF_MIB_VIEW:
                    return "error: end of MIB view";
                default:
                    return String.format("error: %s", variable.getSyntaxString());
            }
        }

        if (variable.getSyntax() == SMIConstants.SYNTAX_NULL) {
            return "null";
        }

        // Counter, Gauges, TimeTicks, etc
        if (variable instanceof AssignableFromLong) {
            return variable.toLong();
        }

        // Integer32
        if (variable instanceof AssignableFromInteger) {
            return variable.toInt();
        }

        // OIDs values
        if (mapOidVariableValues && variable instanceof OID) {
            return mib.map((OID) variable);
        }

        try {
            return variable.toString();
        } catch (Exception e) {
            String message = String.format("error: unable to read variable value. Syntax: %d (%s)", variable.getSyntax(), variable.getSyntaxString());
            logger.error(message);
            return message;
        }
    }

    private void validateTargetVersion(Target<Address> target) {
        if (!this.supportedVersions.contains(target.getVersion())) {
            throw new SnmpClientException(String.format("SNMP version `%s` is disabled", parseSnmpVersion(target.getVersion())));
        }
    }

    public Target<Address> createTarget(
            String address,
            String version,
            int retries,
            int timeout,
            String community,
            String securityName,
            String securityLevel
    ) {
        final int snmpVersion = parseSnmpVersion(version);
        final Target<Address> target;

        if (snmpVersion == SnmpConstants.version3) {
            Objects.requireNonNull(securityName, "security_name is required");
            Objects.requireNonNull(securityLevel, "security_level is required");

            target = new UserTarget<>();
            target.setSecurityLevel(parseSecurityLevel(securityLevel));
            target.setSecurityName(new OctetString(securityName));
            if (address.startsWith("tls")) {
                target.setSecurityModel(SecurityModel.SECURITY_MODEL_TSM);
            }
        } else {
            Objects.requireNonNull(community, "community is required");
            target = new CommunityTarget<>();
            ((CommunityTarget<Address>) target).setCommunity(new OctetString(community));
        }

        final Address targetAddress = GenericAddress.parse(address);
        if (targetAddress == null) {
            throw new IllegalArgumentException(String.format("Invalid or unknown host address: `%s`", address));
        }

        target.setAddress(targetAddress);
        target.setVersion(snmpVersion);
        target.setRetries(retries);
        target.setTimeout(timeout);

        return target;
    }

    private PDUFactory creatPDUFactory(int pduType) {
        return new DefaultPDUFactory(pduType);
    }

    private PDU createPDU(Target<Address> target, int pduType) {
        final PDU pdu;
        if (target.getVersion() == SnmpConstants.version3) {
            pdu = new ScopedPDU();
        } else {
            if (pduType == PDU.V1TRAP) {
                pdu = new PDUv1();
            } else {
                pdu = new PDU();
            }
        }

        pdu.setType(pduType);
        return pdu;
    }

    private static Address parseAddress(String protocol, String host, int port) {
        final String actualProtocol = nonNull(protocol) ? protocol.toLowerCase() : "udp";
        final String actualHost = nonNull(host) ? host : "0.0.0.0";
        final String address = String.format("%s/%d", actualHost, port);

        switch (actualProtocol) {
            case "udp":
                return new UdpAddress(address);
            case "tcp":
                return new TcpAddress(address);
            case "tls":
                return new TlsAddress(address);
            default:
                throw new SnmpClientException(String.format("Invalid transport protocol specified '%s', expecting 'udp', 'tcp' or 'tls'", protocol));
        }
    }

    private static AbstractTransportMapping<? extends Address> createTransport(Address address) throws IOException {
        if (address instanceof TlsAddress) {
            return new TLSTM((TlsAddress) address);
        }

        if (address instanceof TcpAddress) {
            return new DefaultTcpTransportMapping((TcpAddress) address);
        }

        return new DefaultUdpTransportMapping((UdpAddress) address);
    }

    SnmpClient setCloseTimeoutDuration(Duration closeTimeoutDuration) {
        this.closeTimeoutDuration = closeTimeoutDuration;
        return this;
    }

    @Override
    public void close() {
        try {
            // The async close and timeout are necessary here due to an existing
            // race-condition in the SNMP4j ThreadPool class (v3.8.0). Such class
            // might block if the pool #stop gets invoked before the #run reaches
            // the #wait for new tasks, which is never notified. It affects mainly
            // tests, where the client is closed very often.
            CompletableFuture.runAsync(this::closeSnmpClient)
                    .get(closeTimeoutDuration.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            logger.error("Current thread was interrupted while closing the SNMP client. Aborting", e);
            Thread.currentThread().interrupt();
        } catch (TimeoutException e) {
            logger.error("Timed out while closing the SNMP client. Ignoring", e);
        } catch (ExecutionException e) {
            logger.error("Error closing the SNMP client. Ignoring", e.getCause());
        } catch (Exception e) {
            logger.error("Unexpected error closing the SNMP client. Ignoring", e);
        }
    }

    private void closeSnmpClient() {
        try {
            snmp.close();
        } catch (Exception e) {
            logger.error("Error closing SNMP client", e);
        } finally {
            stopCountDownLatch.countDown();
        }
    }

    final Snmp getSnmp() {
        return snmp;
    }

    public boolean isListening() {
        return getSnmp()
                .getMessageDispatcher()
                .getTransportMappings()
                .stream()
                .allMatch(TransportMapping::isListening);
    }
}
