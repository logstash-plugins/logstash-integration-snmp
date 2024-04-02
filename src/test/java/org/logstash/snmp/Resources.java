package org.logstash.snmp;

import java.nio.file.Path;
import java.nio.file.Paths;

public abstract class Resources {

    private static final Path RESOURCES = Paths.get("src/test/resources");

    private Resources() {
    }

    public static Path path(String name) {
        return RESOURCES.resolve(name);
    }

    public static String fullPath(String name) {
        return path(name).toString();
    }
}
