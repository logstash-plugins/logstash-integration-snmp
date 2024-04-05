package org.logstash.snmp;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.layout.PatternLayout;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.fail;


public class LoggerAppender extends AbstractAppender {

    private final Map<String, Map<Level, List<LogEvent>>> events = new HashMap<>();

    public LoggerAppender() {
        super(String.format("LoggerAppender-%d", Thread.currentThread().getId()),
                null,
                PatternLayout.createDefaultLayout(),
                false,
                Property.EMPTY_ARRAY
        );
    }

    @Override
    public void append(final LogEvent event) {
        events.putIfAbsent(event.getLoggerName(), new HashMap<>());
        events.get(event.getLoggerName()).putIfAbsent(event.getLevel(), new ArrayList<>());
        events.get(event.getLoggerName()).get(event.getLevel()).add(event.toImmutable());
    }

    public boolean isEmpty() {
        return events.isEmpty();
    }

    public void assertLogWithMessage(Class<?> clazz, Level level, String format) {
        assertLog(clazz, level, p -> format.equals(p.getMessage().getFormattedMessage()));
    }

    public void assertLogWithFormat(Class<?> clazz, Level level, String format) {
        assertLog(clazz, level, p -> format.equals(p.getMessage().getFormat()));
    }

    public void assertNoLogWithFormat(Class<?> clazz, Level level, String format) {
        try {
            assertLog(clazz, level, p -> format.equals(p.getMessage().getFormat()));
        } catch (AssertionError e) {
            return;
        }

        fail(String.format("%s: received unexpected %s message with format %s", clazz.getName(), level, format));
    }

    public void assertLog(Class<?> clazz, Level level, Predicate<LogEvent> assertion) {
        final Map<Level, List<LogEvent>> byClass = events.get(clazz.getName());
        final String failMessage = String.format("%s: not received expected %s message", clazz.getName(), level);

        if (byClass == null || byClass.isEmpty()) {
            fail(failMessage);
        }

        final List<LogEvent> byLevel = byClass.get(level);
        if (byLevel == null || byLevel.isEmpty()) {
            fail(failMessage);
        }

        if (byLevel.stream().noneMatch(assertion)) {
            fail(failMessage);
        }
    }
}