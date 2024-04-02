package org.logstash.snmp.mib;

public class InvalidMibFileException extends RuntimeException{
    public InvalidMibFileException(final Throwable cause) {
        super(cause);
    }

    public InvalidMibFileException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
