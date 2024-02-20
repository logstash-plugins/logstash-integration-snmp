package org.logstash.snmp.mib;

public class InvalidMbiFileException extends RuntimeException{
    public InvalidMbiFileException(final Throwable cause) {
        super(cause);
    }

    public InvalidMbiFileException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
