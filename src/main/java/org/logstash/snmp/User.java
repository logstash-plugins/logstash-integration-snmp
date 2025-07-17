package org.logstash.snmp;

import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.OctetString;

class User {
    private final UsmUser usmUser;
    private final int securityLevel;

    User(final UsmUser usmUser, final int securityLevel) {
        this.usmUser = usmUser;
        this.securityLevel = securityLevel;
    }

    OctetString getSecurityName() {
        return usmUser.getSecurityName();
    }

    UsmUser getUsmUser() {
        return usmUser;
    }

    int getSecurityLevel() {
        return securityLevel;
    }
}