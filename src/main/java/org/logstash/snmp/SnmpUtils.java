package org.logstash.snmp;

import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthHMAC128SHA224;
import org.snmp4j.security.AuthHMAC192SHA256;
import org.snmp4j.security.AuthHMAC256SHA384;
import org.snmp4j.security.AuthHMAC384SHA512;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

final class SnmpUtils {

    private SnmpUtils() {
        // Hide default constructor
    }

    static int parseSecurityLevel(String securityLevel) {
        switch (securityLevel.toLowerCase()) {
            case "authpriv":
                return SecurityLevel.AUTH_PRIV;
            case "authnopriv":
                return SecurityLevel.AUTH_NOPRIV;
            case "noauthnopriv":
                return SecurityLevel.NOAUTH_NOPRIV;
            default:
                throw new SnmpClientException(String.format("security level '%s' is not supported, expected values are 'noAuthNoPriv', 'authNoPriv', 'authPriv'", securityLevel));
        }
    }

    static int parseSnmpVersion(String version) {
        switch (version) {
            case "1":
                return SnmpConstants.version1;
            case "2c":
                return SnmpConstants.version2c;
            case "3":
                return SnmpConstants.version3;
            default:
                throw new SnmpClientException(String.format("version '%s' is not supported, expected versions are '1', '2c' and '3'", version));
        }
    }

    static String parseSnmpVersion(int version) {
        switch (version) {
            case SnmpConstants.version1:
                return "1";
            case SnmpConstants.version2c:
                return "2c";
            case SnmpConstants.version3:
                return "3";
            default:
                return String.valueOf(version);
        }
    }

    static OID parseAuthProtocol(String authProtocol) {
        if (authProtocol == null) {
            return null;
        }

        switch (authProtocol) {
            case "md5":
                return AuthMD5.ID;
            case "sha":
                return AuthSHA.ID;
            case "hmac128sha224":
                return AuthHMAC128SHA224.ID;
            case "sha2":
            case "hmac192sha256":
                return AuthHMAC192SHA256.ID;
            case "hmac256sha384":
                return AuthHMAC256SHA384.ID;
            case "hmac384sha512":
                return AuthHMAC384SHA512.ID;
            default:
                throw new SnmpClientException(String.format("authentication protocol '%s' is not supported, expected protocols are 'md5', 'sha', and 'sha2'", authProtocol));
        }
    }

    static OID parsePrivProtocol(String privProtocol) {
        if (privProtocol == null) {
            return null;
        }

        switch (privProtocol) {
            case "des":
                return SnmpConstants.usmDESPrivProtocol;
            case "3des":
                return SnmpConstants.usm3DESEDEPrivProtocol;
            case "aes":
            case "aes128":
                return SnmpConstants.usmAesCfb128Protocol;
            case "aes192":
                return SnmpConstants.oosnmpUsmAesCfb192Protocol;
            case "aes256":
                return SnmpConstants.oosnmpUsmAesCfb256Protocol;
            default:
                throw new SnmpClientException(String.format("privacy protocol '%s' is not supported, expected protocols are 'des', '3des', 'aes', 'aes128', 'aes192', and 'aes256'", privProtocol));
        }
    }

    static OctetString parseNullableOctetString(String value) {
        if (value == null) {
            return null;
        }

        return new OctetString(value);
    }
}
