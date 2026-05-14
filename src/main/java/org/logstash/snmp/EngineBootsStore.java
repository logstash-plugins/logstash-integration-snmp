package org.logstash.snmp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.snmp4j.security.UsmTimeEntry;
import org.snmp4j.security.UsmTimeTable;
import org.snmp4j.smi.OctetString;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

final class EngineBootsStore {
    private static final Logger logger = LogManager.getLogger(EngineBootsStore.class);
    private static final String ENGINE_BOOTS_KEY = "engine_boots";
    private static final String LOCAL_ENGINE_ID_KEY = "local_engine_id";
    private static final String REMOTE_ENTRY_PREFIX = "remote.";
    private static final String REMOTE_ENGINE_BOOTS_SUFFIX = ".engine_boots";
    private static final String REMOTE_TIME_DIFF_SUFFIX = ".time_diff";
    private static final Field USM_TIME_TABLE_FIELD = resolveUsmTimeTableField();

    private EngineBootsStore() {
    }

    static synchronized OctetString resolveLocalEngineId(
            final String persistencePath,
            final OctetString localEngineId
    ) {
        if (persistencePath == null || persistencePath.isBlank()) {
            return localEngineId;
        }

        final Path statePath = Paths.get(persistencePath);
        if (!Files.exists(statePath)) {
            return localEngineId;
        }

        final Properties properties = loadProperties(statePath);
        final String persistedEngineId = properties.getProperty(LOCAL_ENGINE_ID_KEY);
        if (persistedEngineId == null || persistedEngineId.isBlank()) {
            return localEngineId;
        }

        try {
            return new OctetString(decodeEngineId(persistedEngineId));
        } catch (RuntimeException e) {
            logger.warn("Unable to read persisted SNMP local engine ID from {}. Reusing a newly generated local engine ID.",
                    statePath,
                    e);
            return localEngineId;
        }
    }

    static synchronized int nextEngineBoots(final String persistencePath, final OctetString localEngineId) {
        if (persistencePath == null || persistencePath.isBlank()) {
            return 0;
        }

        final Path statePath = Paths.get(persistencePath);
        final String engineId = encodeEngineId(localEngineId);
        final Properties properties = new Properties();
        int engineBoots = 0;

        try {
            if (Files.exists(statePath)) {
                try (InputStream inputStream = Files.newInputStream(statePath)) {
                    properties.load(inputStream);
                }

                if (localEngineIdMatches(properties.getProperty(LOCAL_ENGINE_ID_KEY), localEngineId)) {
                    engineBoots = incrementEngineBoots(properties.getProperty(ENGINE_BOOTS_KEY));
                } else {
                    clearRemoteEngineTimeEntries(properties);
                }
            }

            properties.setProperty(LOCAL_ENGINE_ID_KEY, engineId);
            properties.setProperty(ENGINE_BOOTS_KEY, Integer.toString(engineBoots));
            persist(statePath, properties);
            return engineBoots;
        } catch (Exception e) {
            logger.warn("Unable to persist SNMP engine boots state at {}. Falling back to a non-persistent local engine boots counter.",
                    persistencePath,
                    e);
            return 0;
        }
    }

    static synchronized void persistRemoteEngineTimeEntries(
            final String persistencePath,
            final OctetString localEngineId,
            final UsmTimeTable timeTable
    ) {
        if (persistencePath == null || persistencePath.isBlank()) {
            return;
        }

        final Path statePath = Paths.get(persistencePath);
        final Properties properties = loadProperties(statePath);
        properties.setProperty(LOCAL_ENGINE_ID_KEY, encodeEngineId(localEngineId));
        clearRemoteEngineTimeEntries(properties);

        for (PersistedRemoteEngineTime remoteEngineTime : snapshotRemoteEngineTimes(timeTable, localEngineId)) {
            final String keyPrefix = REMOTE_ENTRY_PREFIX + remoteEngineTime.engineId;
            properties.setProperty(keyPrefix + REMOTE_ENGINE_BOOTS_SUFFIX, Integer.toString(remoteEngineTime.engineBoots));
            properties.setProperty(keyPrefix + REMOTE_TIME_DIFF_SUFFIX, Integer.toString(remoteEngineTime.timeDiff));
        }

        try {
            persist(statePath, properties);
        } catch (IOException e) {
            logger.warn("Unable to persist SNMP engine time cache at {}. Continuing with in-memory timeliness data.",
                    persistencePath,
                    e);
        }
    }

    static synchronized List<UsmTimeEntry> loadRemoteEngineTimeEntries(
            final String persistencePath,
            final OctetString localEngineId
    ) {
        if (persistencePath == null || persistencePath.isBlank()) {
            return List.of();
        }

        final Path statePath = Paths.get(persistencePath);
        if (!Files.exists(statePath)) {
            return List.of();
        }

        final Properties properties = loadProperties(statePath);
        if (!localEngineIdMatches(properties.getProperty(LOCAL_ENGINE_ID_KEY), localEngineId)) {
            return List.of();
        }

        final List<UsmTimeEntry> remoteEntries = new ArrayList<>();
        final int currentTime = currentTimeSeconds();

        for (PersistedRemoteEngineTime remoteEngineTime : readRemoteEngineTimeEntries(properties)) {
            final int engineTime = currentTime + remoteEngineTime.timeDiff;
            remoteEntries.add(new UsmTimeEntry(
                    new OctetString(decodeEngineId(remoteEngineTime.engineId)),
                    remoteEngineTime.engineBoots,
                    engineTime
            ));
        }

        return remoteEntries;
    }

    static String remoteEngineTimeSignature(final UsmTimeTable timeTable, final OctetString localEngineId) {
        final StringBuilder signature = new StringBuilder();

        for (PersistedRemoteEngineTime remoteEngineTime : snapshotRemoteEngineTimes(timeTable, localEngineId)) {
            if (signature.length() > 0) {
                signature.append('|');
            }
            signature.append(remoteEngineTime.engineId)
                    .append(':')
                    .append(remoteEngineTime.engineBoots)
                    .append(':')
                    .append(remoteEngineTime.timeDiff);
        }

        return signature.toString();
    }

    private static int incrementEngineBoots(final String value) {
        try {
            final int storedValue = Integer.parseInt(value);
            if (storedValue < 0) {
                return 0;
            }
            if (storedValue == Integer.MAX_VALUE) {
                return Integer.MAX_VALUE;
            }
            return storedValue + 1;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static Properties loadProperties(final Path statePath) {
        final Properties properties = new Properties();

        try (InputStream inputStream = Files.newInputStream(statePath)) {
            properties.load(inputStream);
        } catch (IOException e) {
            logger.warn("Unable to read SNMP engine state from {}. Recreating the persistence file.", statePath, e);
        }

        return properties;
    }

    private static List<PersistedRemoteEngineTime> snapshotRemoteEngineTimes(
            final UsmTimeTable timeTable,
            final OctetString localEngineId
    ) {
        final List<PersistedRemoteEngineTime> remoteEntries = new ArrayList<>();
        final Hashtable<?, ?> entries = extractRemoteTimeTableEntries(timeTable);

        for (Object value : entries.values()) {
            if (!(value instanceof UsmTimeEntry)) {
                continue;
            }

            final UsmTimeEntry entry = (UsmTimeEntry) value;
            if (entry.getEngineID().equals(localEngineId)) {
                continue;
            }

            remoteEntries.add(new PersistedRemoteEngineTime(
                    encodeEngineId(entry.getEngineID()),
                    entry.getEngineBoots(),
                    entry.getTimeDiff()
            ));
        }

        remoteEntries.sort(Comparator.comparing(remoteEngineTime -> remoteEngineTime.engineId));
        return remoteEntries;
    }

    private static List<PersistedRemoteEngineTime> readRemoteEngineTimeEntries(final Properties properties) {
        final List<PersistedRemoteEngineTime> remoteEntries = new ArrayList<>();

        for (String key : properties.stringPropertyNames()) {
            if (!key.startsWith(REMOTE_ENTRY_PREFIX) || !key.endsWith(REMOTE_ENGINE_BOOTS_SUFFIX)) {
                continue;
            }

            final String engineId = key.substring(REMOTE_ENTRY_PREFIX.length(), key.length() - REMOTE_ENGINE_BOOTS_SUFFIX.length());
            final String timeDiffKey = REMOTE_ENTRY_PREFIX + engineId + REMOTE_TIME_DIFF_SUFFIX;
            final String engineBootsValue = properties.getProperty(key);
            final String timeDiffValue = properties.getProperty(timeDiffKey);

            if (timeDiffValue == null) {
                continue;
            }

            try {
                remoteEntries.add(new PersistedRemoteEngineTime(
                        engineId,
                        Integer.parseInt(engineBootsValue),
                        Integer.parseInt(timeDiffValue)
                ));
            } catch (RuntimeException e) {
                logger.warn("Unable to parse SNMP engine time cache entry for engine {}. Skipping it.", engineId, e);
            }
        }

        remoteEntries.sort(Comparator.comparing(remoteEngineTime -> remoteEngineTime.engineId));
        return remoteEntries;
    }

    private static Hashtable<?, ?> extractRemoteTimeTableEntries(final UsmTimeTable timeTable) {
        try {
            return (Hashtable<?, ?>) USM_TIME_TABLE_FIELD.get(timeTable);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Unable to access SNMP4J USM time table entries", e);
        }
    }

    private static Field resolveUsmTimeTableField() {
        try {
            final Field tableField = UsmTimeTable.class.getDeclaredField("table");
            tableField.setAccessible(true);
            return tableField;
        } catch (NoSuchFieldException e) {
            throw new IllegalStateException("Unable to locate SNMP4J USM time table storage", e);
        }
    }

    private static void clearRemoteEngineTimeEntries(final Properties properties) {
        final List<String> remoteKeys = new ArrayList<>();
        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith(REMOTE_ENTRY_PREFIX)) {
                remoteKeys.add(key);
            }
        }
        remoteKeys.forEach(properties::remove);
    }

    private static int currentTimeSeconds() {
        return (int) (System.nanoTime() / 1_000_000_000L);
    }

    private static boolean localEngineIdMatches(final String persistedEngineId, final OctetString localEngineId) {
        if (persistedEngineId == null || persistedEngineId.isBlank()) {
            return false;
        }

        try {
            return new OctetString(decodePersistedEngineId(persistedEngineId)).equals(localEngineId);
        } catch (RuntimeException e) {
            logger.warn("Unable to parse persisted SNMP local engine ID {}. Recreating the persistence file.", persistedEngineId, e);
            return false;
        }
    }

    private static String encodeEngineId(final OctetString engineId) {
        final byte[] bytes = engineId.getValue();
        final StringBuilder builder = new StringBuilder(bytes.length * 2);

        for (byte value : bytes) {
            builder.append(Character.forDigit((value >> 4) & 0x0F, 16));
            builder.append(Character.forDigit(value & 0x0F, 16));
        }

        return builder.toString();
    }

    private static byte[] decodePersistedEngineId(final String encodedEngineId) {
        if (encodedEngineId.indexOf(':') >= 0) {
            return OctetString.fromHexString(encodedEngineId).getValue();
        }

        return decodeEngineId(encodedEngineId);
    }

    private static byte[] decodeEngineId(final String encodedEngineId) {
        if ((encodedEngineId.length() & 1) != 0) {
            throw new IllegalArgumentException("SNMP engine ID must contain an even number of hexadecimal digits");
        }

        final byte[] decoded = new byte[encodedEngineId.length() / 2];
        for (int index = 0; index < encodedEngineId.length(); index += 2) {
            decoded[index / 2] = (byte) Integer.parseInt(encodedEngineId.substring(index, index + 2), 16);
        }

        return decoded;
    }

    private static final class PersistedRemoteEngineTime {
        private final String engineId;
        private final int engineBoots;
        private final int timeDiff;

        private PersistedRemoteEngineTime(final String engineId, final int engineBoots, final int timeDiff) {
            this.engineId = engineId;
            this.engineBoots = engineBoots;
            this.timeDiff = timeDiff;
        }
    }

    private static void persist(final Path statePath, final Properties properties) throws IOException {
        final Path parent = statePath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        final Path tempFile = Files.createTempFile(parent, statePath.getFileName().toString(), ".tmp");
        try {
            try (OutputStream outputStream = Files.newOutputStream(tempFile,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                properties.store(outputStream, "SNMP engine boots state");
            }

            Files.move(tempFile, statePath,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }
}