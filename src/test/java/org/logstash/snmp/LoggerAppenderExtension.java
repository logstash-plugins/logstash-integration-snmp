package org.logstash.snmp;

import org.apache.logging.log4j.core.Logger;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class LoggerAppenderExtension implements BeforeEachCallback, AfterEachCallback {
    private final Logger logger;
    private final LoggerAppender appender = new LoggerAppender();

    public LoggerAppenderExtension(org.apache.logging.log4j.Logger logger) {
        this.logger = (Logger) logger;
    }

    public LoggerAppender getAppender() {
        return appender;
    }

    @Override
    public void beforeEach(final ExtensionContext context) {
        appender.start();
        logger.addAppender(appender);
    }

    @Override
    public void afterEach(final ExtensionContext context) {
        logger.removeAppender(appender);
    }
}
