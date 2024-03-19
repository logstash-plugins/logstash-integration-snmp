package org.logstash.snmp;

import org.junit.jupiter.api.Test;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthHMAC128SHA224;
import org.snmp4j.security.AuthHMAC192SHA256;
import org.snmp4j.security.AuthHMAC256SHA384;
import org.snmp4j.security.AuthHMAC384SHA512;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.smi.OctetString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SnmpUtilsTest {

    @Test
    void shouldParseSecurityLevel() {
        assertEquals(SecurityLevel.AUTH_PRIV, SnmpUtils.parseSecurityLevel("authpriv"));
        assertEquals(SecurityLevel.AUTH_NOPRIV, SnmpUtils.parseSecurityLevel("authnopriv"));
        assertEquals(SecurityLevel.NOAUTH_NOPRIV, SnmpUtils.parseSecurityLevel("noauthnopriv"));
        assertThrows(SnmpClientException.class, () -> SnmpUtils.parseSecurityLevel("foo"));
    }

    @Test
    void shouldParseSnmpVersion() {
        assertEquals(SnmpConstants.version1, SnmpUtils.parseSnmpVersion("1"));
        assertEquals(SnmpConstants.version2c, SnmpUtils.parseSnmpVersion("2c"));
        assertEquals(SnmpConstants.version3, SnmpUtils.parseSnmpVersion("3"));
        assertThrows(SnmpClientException.class, () -> SnmpUtils.parseSnmpVersion("4"));
    }

    @Test
    void shouldParseSnmpVersionFromInteger() {
        assertEquals("1", SnmpUtils.parseSnmpVersion(SnmpConstants.version1));
        assertEquals("2c", SnmpUtils.parseSnmpVersion(SnmpConstants.version2c));
        assertEquals("3", SnmpUtils.parseSnmpVersion(SnmpConstants.version3));
        assertEquals("99", SnmpUtils.parseSnmpVersion(99));
    }

    @Test
    void shouldParseAuthProtocol() {
        assertNull(SnmpUtils.parseAuthProtocol(null));
        assertEquals(AuthMD5.ID, SnmpUtils.parseAuthProtocol("md5"));
        assertEquals(AuthSHA.ID, SnmpUtils.parseAuthProtocol("sha"));
        assertEquals(AuthHMAC128SHA224.ID, SnmpUtils.parseAuthProtocol("hmac128sha224"));
        assertEquals(AuthHMAC192SHA256.ID, SnmpUtils.parseAuthProtocol("sha2"));
        assertEquals(AuthHMAC192SHA256.ID, SnmpUtils.parseAuthProtocol("hmac192sha256"));
        assertEquals(AuthHMAC256SHA384.ID, SnmpUtils.parseAuthProtocol("hmac256sha384"));
        assertEquals(AuthHMAC384SHA512.ID, SnmpUtils.parseAuthProtocol("hmac384sha512"));
        assertThrows(SnmpClientException.class, () -> SnmpUtils.parseAuthProtocol("bar"));
    }

    @Test
    void shouldParsePrivProtocol() {
        assertNull(SnmpUtils.parsePrivProtocol(null));
        assertEquals(SnmpConstants.usmDESPrivProtocol, SnmpUtils.parsePrivProtocol("des"));
        assertEquals(SnmpConstants.usm3DESEDEPrivProtocol, SnmpUtils.parsePrivProtocol("3des"));
        assertEquals(SnmpConstants.usmAesCfb128Protocol, SnmpUtils.parsePrivProtocol("aes"));
        assertEquals(SnmpConstants.usmAesCfb128Protocol, SnmpUtils.parsePrivProtocol("aes128"));
        assertEquals(SnmpConstants.oosnmpUsmAesCfb192Protocol, SnmpUtils.parsePrivProtocol("aes192"));
        assertEquals(SnmpConstants.oosnmpUsmAesCfb256Protocol, SnmpUtils.parsePrivProtocol("aes256"));
        assertThrows(SnmpClientException.class, () -> SnmpUtils.parsePrivProtocol("foo"));
    }

    @Test
    void shouldParseNullableOctetString() {
        assertNull(SnmpUtils.parseNullableOctetString(null));
        assertEquals(new OctetString("foo"), SnmpUtils.parseNullableOctetString("foo"));
    }
}