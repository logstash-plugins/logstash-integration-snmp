package org.logstash.snmp;

import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.MessageProcessingModel;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.logstash.snmp.SnmpUtils.parseAuthProtocol;
import static org.logstash.snmp.SnmpUtils.parseNullableOctetString;
import static org.logstash.snmp.SnmpUtils.parsePrivProtocol;
import static org.logstash.snmp.SnmpUtils.parseSecurityLevel;

/**
 * Helper class for sending SNMP trap messages. It's meant for tests purpose only.
 */
public class SnmpTestTrapSender {

    private final Snmp snmp;

    public SnmpTestTrapSender(int port) {
        this.snmp = createSnmpSession(port);
    }

    public void sendTrapV1(String address, String community, Map<String, Object> bindings) {
        final CommunityTarget<Address> target = new CommunityTarget<>(
                GenericAddress.parse(address),
                new OctetString(community)
        );

        final PDUv1 pdu = new PDUv1();
        addVariableBindings(pdu, bindings);
        send(pdu, target);
    }

    public void sendTrapV2c(String address, String community, Map<String, Object> bindings) {
        final PDU pdu = new PDU();
        pdu.setType(PDU.TRAP);
        addVariableBindings(pdu, bindings);

        final CommunityTarget<Address> target = new CommunityTarget<>(
                GenericAddress.parse(address),
                new OctetString(community)
        );

        target.setVersion(SnmpConstants.version2c);
        target.setSecurityModel(SecurityModel.SECURITY_MODEL_SNMPv2c);
        send(pdu, target);
    }

    public void sendTrapV3(
            String address,
            String securityName,
            String authProtocol,
            String authPassphrase,
            String privProtocol,
            String privPassphrase,
            String securityLevel,
            Map<String, Object> bindings) {
        try {
            final USM usm = new USM();
            usm.addUser(new UsmUser(
                    new OctetString(securityName),
                    parseAuthProtocol(authProtocol),
                    parseNullableOctetString(authPassphrase),
                    parsePrivProtocol(privProtocol),
                    parseNullableOctetString(privPassphrase)
            ));

            snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

            final ScopedPDU pdu = new ScopedPDU();
            pdu.setType(PDU.TRAP);
            addVariableBindings(pdu, bindings);

            final Target<Address> target = new UserTarget<>();
            target.setAddress(GenericAddress.parse(address));
            target.setSecurityLevel(parseSecurityLevel(securityLevel));
            target.setSecurityName(new OctetString(securityName));
            target.setVersion(SnmpConstants.version3);
            target.setSecurityModel(SecurityModel.SECURITY_MODEL_USM);

            send(pdu, target);
        } finally {
            cleanupSnmpMessageDispatcherMPv3Model();
        }
    }

    private void cleanupSnmpMessageDispatcherMPv3Model() {
        final MessageDispatcher messageDispatcher = snmp.getMessageDispatcher();
        final MessageProcessingModel existingMPv3Model = messageDispatcher.getMessageProcessingModel(MPv3.ID);
        if (existingMPv3Model != null) {
            messageDispatcher.removeMessageProcessingModel(existingMPv3Model);
        }
    }

    private void send(PDU pdu, Target<Address> target) {
        try {
            final ResponseEvent<Address> response = snmp.send(pdu, target);
            if (response != null && response.getError() != null) {
                throw new RuntimeException(response.getError());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void addVariableBindings(PDU pdu, Map<String, Object> bindings) {
        for (final Map.Entry<String, Object> binding : bindings.entrySet()) {
            final Variable variable;
            if (binding.getValue() instanceof Variable) {
                variable = (Variable) binding.getValue();
            } else {
                variable = new OctetString(String.valueOf(binding.getValue()));
            }

            pdu.add(new VariableBinding(new OID(binding.getKey()), variable));
        }
    }

    private static Snmp createSnmpSession(int port) {
        final Snmp snmp = new Snmp();
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());

        try {
            snmp.addTransportMapping(new DefaultTcpTransportMapping(new TcpAddress(port)));
            snmp.addTransportMapping(new DefaultUdpTransportMapping(new UdpAddress(port), true));
            snmp.listen();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return snmp;
    }

    public void close() {
        try {
            CompletableFuture.runAsync(() -> {
                try {
                    snmp.close();
                } catch (IOException e) {
                    // Ignore
                }
            }).get(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (TimeoutException e) {
            // Ignore
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }
}
