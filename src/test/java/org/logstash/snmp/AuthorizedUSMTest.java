package org.logstash.snmp;

import org.junit.jupiter.api.Test;
import org.snmp4j.asn1.BERInputStream;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.mp.StatusInformation;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.UsmSecurityParameters;
import org.snmp4j.security.UsmSecurityStateReference;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.OctetString;

import java.io.IOException;
import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class AuthorizedUSMTest {

    @Test
    void shouldNotProcessIncomingMessageWhenSecurityLevelIsLowerThanDefined() throws IOException {
        final AuthorizedUSM usm = new AuthorizedUSM(
                SecurityProtocols.getInstance().addDefaultProtocols(),
                new OctetString(MPv3.createLocalEngineID()),
                0
        );

        usm.addUser(new AuthorizedUSM.User(new UsmUser(
                        new OctetString("foo"),
                        AuthMD5.ID,
                        new OctetString("barbarbar"),
                        SnmpConstants.usmDESPrivProtocol,
                        new OctetString("foofoofoo")),
                        SecurityLevel.AUTH_PRIV
                )
        );

        final UsmSecurityParameters usmSecurityParameters = new UsmSecurityParameters();
        usmSecurityParameters.setUserName(new OctetString("foo"));
        final StatusInformation statusInfo = new StatusInformation();

        final int result = usm.processIncomingMsg(3, 0, usmSecurityParameters, null, SecurityLevel.NOAUTH_NOPRIV, null, null, null, null, null, null, null, statusInfo);

        assertEquals(SnmpConstants.SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL, result);
        assertEquals(SnmpConstants.usmStatsUnsupportedSecLevels, statusInfo.getErrorIndication().getOid());
    }

    @Test
    void shouldProcessIncomingMessageWhenSecurityLevelIsHigherThanDefined() throws IOException {
        final AuthorizedUSM usm = new AuthorizedUSM(
                SecurityProtocols.getInstance().addDefaultProtocols(),
                new OctetString(MPv3.createLocalEngineID()),
                0
        );

        usm.addUser(new AuthorizedUSM.User(new UsmUser(
                        new OctetString("foo"),
                        AuthMD5.ID,
                        new OctetString("secretbar"),
                        SnmpConstants.usmDESPrivProtocol,
                        new OctetString("secretfoo")),
                        SecurityLevel.AUTH_NOPRIV
                )
        );

        final UsmSecurityParameters usmSecurityParameters = new UsmSecurityParameters();
        usmSecurityParameters.setUserName(new OctetString("foo"));
        final StatusInformation statusInfo = new StatusInformation();

        final int result = usm.processIncomingMsg(3, 0, usmSecurityParameters, null, SecurityLevel.AUTH_PRIV, new BERInputStream(ByteBuffer.allocate(16)), null, new OctetString(), new OctetString("foo"), null, null, new UsmSecurityStateReference(), statusInfo);

        assertNotEquals(SnmpConstants.SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL, result);
    }
}