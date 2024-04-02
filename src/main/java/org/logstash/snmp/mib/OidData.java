package org.logstash.snmp.mib;

import java.util.Objects;

public final class OidData {
    private final String type;
    private final String name;
    private final String moduleName;

    public OidData(String type, String name, String moduleName) {
        this.type = type;
        this.name = name;
        this.moduleName = moduleName;
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
                Objects.equals(this.moduleName, that.moduleName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, name, moduleName);
    }

    @Override
    public String toString() {
        return "OidData[" +
                "type=" + type + ", " +
                "name=" + name + ", " +
                "moduleName=" + moduleName + ']';
    }
}
