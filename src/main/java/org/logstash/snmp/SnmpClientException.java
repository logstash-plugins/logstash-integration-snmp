package org.logstash.snmp;

public class SnmpClientException extends RuntimeException {
    public SnmpClientException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public SnmpClientException(final String message) {
        super(message);
    }
}
