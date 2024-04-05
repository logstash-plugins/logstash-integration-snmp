package org.logstash.snmp.trap;

import org.snmp4j.smi.Address;
import org.snmp4j.smi.TransportIpAddress;

import java.util.Map;

public class SnmpTrapMessage {
    private final int version;
    private final byte[] securityName;
    private final Address peerAddress;
    private final Map<String, Object> trapEvent;
    private final Map<String, Object> formattedVariableBindings;

    public SnmpTrapMessage(
            int version,
            byte[] securityName,
            Address peerAddress,
            Map<String, Object> trapEvent,
            Map<String, Object> formattedVariableBindings
    ) {
        this.version = version;
        this.securityName = securityName;
        this.peerAddress = peerAddress;
        this.trapEvent = trapEvent;
        this.formattedVariableBindings = formattedVariableBindings;
    }

    public int getVersion() {
        return version;
    }

    public String getSecurityNameString() {
        return new String(securityName);
    }

    public Map<String, Object> getTrapEvent() {
        return trapEvent;
    }

    public Map<String, Object> getFormattedVariableBindings() {
        return formattedVariableBindings;
    }

    public String getPeerIpAddress() {
        if (peerAddress instanceof TransportIpAddress) {
            return ((TransportIpAddress) peerAddress).getInetAddress().getHostAddress();
        } else {
            return peerAddress.toString();
        }
    }
}