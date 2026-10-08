package org.logstash.snmp.mib;

import java.util.Map;
import java.util.Objects;

public final class OidData {
    private final String type;
    private final String name;
    private final String moduleName;
    private final Map<Integer, String> namedValues;

    public OidData(String type, String name, String moduleName) {
        this(type, name, moduleName, Map.of());
    }

    public OidData(String type, String name, String moduleName, Map<Integer, String> namedValues) {
        this.type = type;
        this.name = name;
        this.moduleName = moduleName;
        this.namedValues = namedValues == null ? Map.of() : namedValues;
    }

    public String getType() {
        return type;
    }

    public String getName() {
        return name;
    }

    public String getModuleName() {
        return moduleName;
    }

    public Map<Integer, String> getNamedValues() {
        return namedValues;
    }

    public boolean equalsIgnoreModuleName(OidData other) {
        return Objects.equals(this.type, other.type) &&
                Objects.equals(this.name, other.name);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        OidData that = (OidData) obj;
        return Objects.equals(this.type, that.type) &&
                Objects.equals(this.name, that.name) &&
                Objects.equals(this.moduleName, that.moduleName) &&
                Objects.equals(this.namedValues, that.namedValues);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, name, moduleName, namedValues);
    }

    @Override
    public String toString() {
        return "OidData[" +
                "type=" + type + ", " +
                "name=" + name + ", " +
                "moduleName=" + moduleName + ", " +
                "namedValues=" + namedValues + ']';
    }
}
