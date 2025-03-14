package org.logstash.snmp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.snmp4j.TransportStateReference;
import org.snmp4j.asn1.BERInputStream;
import org.snmp4j.asn1.BEROutputStream;
import org.snmp4j.event.CounterEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.mp.StatusInformation;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.SecurityParameters;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.SecurityStateReference;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmSecurityParameters;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

class AuthorizedUSM extends USM {
    private static final Logger logger = LogManager.getLogger(AuthorizedUSM.class);
    private final Map<OctetString, Integer> usersMinimalSecurityLevels = new HashMap<>();

    AuthorizedUSM(
            final SecurityProtocols instance,
            final OctetString localEngineID,
            final int engineBootCount
    ) {
        super(instance, localEngineID, engineBootCount);
    }

    void addUser(final User user) {
        super.addUser(user.usmUser);
        usersMinimalSecurityLevels.put(user.usmUser.getSecurityName(), user.minimumSecurityLevel);
    }

    @Override
    public int processIncomingMsg(
            final int snmpVersion,
            final int maxMessageSize,
            final SecurityParameters securityParameters,
            final SecurityModel securityModel,
            final int securityLevel,
            final BERInputStream wholeMsg,
            final TransportStateReference tmStateReference,
            final OctetString securityEngineID,
            final OctetString securityName,
            final BEROutputStream scopedPDU,
            final Integer32 maxSizeResponseScopedPDU,
            final SecurityStateReference securityStateReference,
            final StatusInformation statusInfo
    ) throws IOException {
        UsmSecurityParameters usmSecurityParameters = (UsmSecurityParameters) securityParameters;
        final int userMinimalSecurityLevel = usersMinimalSecurityLevels.getOrDefault(usmSecurityParameters.getUserName(), 0);
        if (securityLevel < userMinimalSecurityLevel) {
            if (logger.isDebugEnabled()) {
                logger.debug("RFC3414 §3.2.5 - Unsupported security level: {} by user {} authProtocol={}, privProtocol={}",
                        securityLevel, usmSecurityParameters.getUserName(), usmSecurityParameters.getAuthenticationProtocol(), usmSecurityParameters.getPrivacyProtocol());
            }

            final CounterEvent event = new CounterEvent(this, SnmpConstants.usmStatsUnsupportedSecLevels);
            fireIncrementCounter(event);
            statusInfo.setErrorIndication(new VariableBinding(event.getOid(), event.getCurrentValue()));
            return SnmpConstants.SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL;
        }

        return super.processIncomingMsg(
                snmpVersion,
                maxMessageSize,
                securityParameters,
                securityModel,
                securityLevel,
                wholeMsg,
                tmStateReference,
                securityEngineID,
                securityName,
                scopedPDU,
                maxSizeResponseScopedPDU,
                securityStateReference,
                statusInfo
        );
    }

    static class User {
        private final UsmUser usmUser;
        private final int minimumSecurityLevel;

        User(final UsmUser usmUser, final int minimumSecurityLevel) {
            this.usmUser = usmUser;
            this.minimumSecurityLevel = minimumSecurityLevel;
        }
    }
}