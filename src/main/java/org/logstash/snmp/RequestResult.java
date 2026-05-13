package org.logstash.snmp;

import java.util.Map;

public class RequestResult {
    private final Map<String, Object> data;
    private final boolean hasErrors;

    public RequestResult(Map<String, Object> data, boolean hasErrors) {
        this.data = data;
        this.hasErrors = hasErrors;
    }

    public Map<String, Object> data() {
        return data;
    }

    public boolean hasErrors() {
        return hasErrors;
    }
}
