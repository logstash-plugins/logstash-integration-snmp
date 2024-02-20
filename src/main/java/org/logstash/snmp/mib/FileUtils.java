package org.logstash.snmp.mib;

import java.nio.file.Path;

final class FileUtils {

    private FileUtils() {
        // Hide default constructor
    }

    static String getFileExtension(Path file) {
        final String fileName = file.getFileName().toString();
        final int lastDot = fileName.lastIndexOf('.');
        if (lastDot > -1) {
            return fileName.substring(lastDot + 1);
        } else {
            return "";
        }
    }

    static String getFileNameWithoutExtension(Path path) {
        final String fileName = path.getFileName().toString();
        final int lastDot = fileName.lastIndexOf(".");
        if (lastDot > -1) {
            return fileName.substring(0, lastDot);
        }

        return fileName;
    }
}
