package org.logstash.snmp;

import java.util.Map;

public class SnmpClientException extends RuntimeException {
    private final Map<String, ?> partialResult;

    public SnmpClientException(final String message, final Throwable cause) {
        this(message, cause, null);
    }

    public SnmpClientException(final String message) {
        this(message, null, null);
    }

    public SnmpClientException(final String message, final Throwable cause, final Map<String, ?> partialResult) {
        super(message, cause);
        this.partialResult = partialResult;
    }

    public Map<String, ?> getPartialResult() {
        return partialResult;
    }
}
