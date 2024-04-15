package org.logstash.snmp;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.snmp4j.CommunityTarget;
import org.snmp4j.Target;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SnmpClientRequestAggregatorTest {
    private static final long RESULT_TIMEOUT_MILLIS = 1_000;
    private static final int THREADS = 1;
    private static final String THREAD_POOL_NAME = "SnmpClientRequestAggregatorTest";
    private static final OID[] SOME_OIDS = new OID[]{new OID("1"), new OID("1.2")};
    private static final Target<Address> COMMUNIT_TARGET = new CommunityTarget<>(GenericAddress.parse("127.0.0.1/161"), new OctetString("public"));

    private AutoCloseable mocks;

    @RegisterExtension
    private final LoggerAppenderExtension loggerExt = new LoggerAppenderExtension(LogManager.getLogger(SnmpClientRequestAggregator.class));

    @Mock
    private SnmpClient snmpClient;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
    }

    @AfterEach
    void tearDown() throws Exception {
        mocks.close();
    }

    @Test
    void awaitShouldBlockUntilAllRequestAreDone() throws Exception {
        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            final int minimumWaitingMillis = 1000;
            final SnmpClientRequestAggregator.Request slowRequest = mock(SnmpClientRequestAggregator.Request.class);
            final CompletableFuture<Void> slowRequestFuture = new CompletableFuture<>();
            final SnmpClientRequestAggregator.Request fastRequest = aggregator.createRequest(snmpClient);

            when(slowRequest.toCompletableFuture())
                    .thenReturn(slowRequestFuture);

            new Thread(() -> {
                try {
                    Thread.sleep(minimumWaitingMillis);
                    slowRequestFuture.complete(null);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }).start();

            long start = System.currentTimeMillis();
            aggregator.await(
                    new SnmpClientRequestAggregator.Request[]{slowRequest, fastRequest},
                    minimumWaitingMillis + 1000
            );

            long finish = System.currentTimeMillis();
            long timeElapsed = finish - start;
            assertTrue(timeElapsed >= minimumWaitingMillis);
        }
    }

    @Test
    void requestWithGetOperationShouldInvokeClientGet() throws Exception {
        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            aggregator.createRequest(snmpClient).get(COMMUNIT_TARGET, SOME_OIDS);
        }

        verify(snmpClient).get(COMMUNIT_TARGET, SOME_OIDS);
    }

    @Test
    void requestWithGetOperationResponseShouldAddToResult() throws Exception {
        when(snmpClient.get(COMMUNIT_TARGET, SOME_OIDS))
                .thenReturn(Map.of("foo", "bar"));

        final AtomicReference<Map<String, Object>> resultRef = new AtomicReference<>();
        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            final SnmpClientRequestAggregator.Request request = aggregator.createRequest(snmpClient);
            request.get(COMMUNIT_TARGET, SOME_OIDS);
            request.getResultAsync(resultRef::set).get(RESULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        }

        final Map<String, Object> result = resultRef.get();
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("bar", result.get("foo"));
    }

    @Test
    void requestWithGetOperationWithEmptyResponseShouldLog() throws Exception {
        when(snmpClient.get(COMMUNIT_TARGET, SOME_OIDS))
                .thenReturn(Map.of());

        final String expectedLogDetails = SnmpClientRequestAggregator.Request
                .createLogDetails(COMMUNIT_TARGET, SOME_OIDS, Map.of())
                .toString();

        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            aggregator.createRequest(snmpClient).get(COMMUNIT_TARGET, SOME_OIDS);
        }

        loggerExt.getAppender().assertLogWithMessage(
                SnmpClientRequestAggregator.class,
                Level.DEBUG,
                String.format("`get` operation returned no response. %s", expectedLogDetails)
        );
    }

    @Test
    void requestWithGetOperationErrorShouldLogException() throws Exception {
        when(snmpClient.get(COMMUNIT_TARGET, SOME_OIDS))
                .thenAnswer(p -> {
                    throw new UnknownHostException();
                });

        final String expectedLogDetails = SnmpClientRequestAggregator.Request
                .createLogDetails(COMMUNIT_TARGET, SOME_OIDS, Map.of())
                .toString();

        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            aggregator.createRequest(snmpClient).get(COMMUNIT_TARGET, SOME_OIDS);
        }

        final String expectedLogMessage = String.format("error invoking `get` operation, ignoring. %s", expectedLogDetails);
        loggerExt.getAppender().assertLog(
                SnmpClientRequestAggregator.class,
                Level.ERROR,
                (log) -> expectedLogMessage.equals(log.getMessage().getFormattedMessage()) &&
                        log.getThrown() instanceof UnknownHostException
        );
    }

    @Test
    void requestWithWalkOperationShouldInvokeClientWalk() {
        final OID oid = new OID("1");

        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            aggregator.createRequest(snmpClient).walk(COMMUNIT_TARGET, oid);
        }

        verify(snmpClient).walk(COMMUNIT_TARGET, oid);
    }

    @Test
    void requestWithWalkOperationResponseShouldAddToResult() throws Exception {
        final OID oid = new OID("1");

        when(snmpClient.walk(COMMUNIT_TARGET, oid))
                .thenReturn(Map.of("walk", "talk"));

        final AtomicReference<Map<String, Object>> resultRef = new AtomicReference<>();
        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            final SnmpClientRequestAggregator.Request request = aggregator.createRequest(snmpClient);
            request.walk(COMMUNIT_TARGET, oid);
            request.getResultAsync(resultRef::set).get(RESULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        }

        final Map<String, Object> result = resultRef.get();
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("talk", result.get("walk"));
    }

    @Test
    void requestWithWalkOperationWithEmptyResponseShouldLog() {
        final OID oid = new OID("1.2.3");

        when(snmpClient.walk(COMMUNIT_TARGET, oid))
                .thenReturn(Map.of());

        final String expectedLogDetails = SnmpClientRequestAggregator.Request
                .createLogDetails(COMMUNIT_TARGET, new OID[]{oid}, Map.of())
                .toString();

        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            aggregator.createRequest(snmpClient).walk(COMMUNIT_TARGET, oid);
        }

        loggerExt.getAppender().assertLogWithMessage(
                SnmpClientRequestAggregator.class,
                Level.DEBUG,
                String.format("`walk` operation returned no response. %s", expectedLogDetails)
        );
    }

    @Test
    void requestWithWalkOperationErrorShouldLogException() {
        final OID oid = new OID("1.2.3");

        when(snmpClient.walk(COMMUNIT_TARGET, oid)).thenAnswer(p -> {
            throw new RuntimeException("foo");
        });

        final String expectedLogDetails = SnmpClientRequestAggregator.Request
                .createLogDetails(COMMUNIT_TARGET, new OID[]{oid}, Map.of())
                .toString();

        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            aggregator.createRequest(snmpClient).walk(COMMUNIT_TARGET, oid);
        }

        final String expectedLogMessage = String.format("error invoking `walk` operation, ignoring. %s", expectedLogDetails);
        loggerExt.getAppender().assertLog(
                SnmpClientRequestAggregator.class,
                Level.ERROR,
                (log) -> expectedLogMessage.equals(log.getMessage().getFormattedMessage()) &&
                        log.getThrown() instanceof RuntimeException
        );
    }

    @Test
    void requestWithTableOperationShouldInvokeClientTable() {
        final Target<Address> target = mock();
        final String tableName = "fooBarTable";

        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            aggregator.createRequest(snmpClient).table(target, tableName, SOME_OIDS);
        }

        verify(snmpClient).table(target, tableName, SOME_OIDS);
    }

    @Test
    void requestWithTableOperationResponseShouldAddToResult() throws Exception {
        final String tableName = "fooBarTable";
        final OID[] columns = new OID[]{new OID("1")};

        when(snmpClient.table(COMMUNIT_TARGET, tableName, columns))
                .thenReturn(Map.of(tableName, List.of(Map.of("1", "book"))));

        final AtomicReference<Map<String, Object>> resultRef = new AtomicReference<>();
        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            final SnmpClientRequestAggregator.Request request = aggregator.createRequest(snmpClient);
            request.table(COMMUNIT_TARGET, tableName, columns);
            request.getResultAsync(resultRef::set).get(RESULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        }

        final Map<String, Object> result = resultRef.get();
        assertNotNull(result);
        assertEquals(1, result.size());

        @SuppressWarnings("unchecked") final List<Map<String, Object>> rows = (List<Map<String, Object>>) result.get(tableName);
        assertEquals(1, rows.size());
        assertEquals("book", rows.get(0).get("1"));
    }

    @Test
    void requestWithTableOperationWithEmptyResponseShouldLog() {
        final String tableName = "fooBarTable";

        when(snmpClient.table(COMMUNIT_TARGET, tableName, SOME_OIDS))
                .thenReturn(Map.of());

        final String expectedLogDetails = SnmpClientRequestAggregator.Request
                .createLogDetails(COMMUNIT_TARGET, SOME_OIDS, Map.of("table_name", tableName))
                .toString();

        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            aggregator.createRequest(snmpClient).table(COMMUNIT_TARGET, tableName, SOME_OIDS);
        }

        loggerExt.getAppender().assertLogWithMessage(
                SnmpClientRequestAggregator.class,
                Level.DEBUG,
                String.format("`table` operation returned no response. %s", expectedLogDetails)
        );
    }

    @Test
    void requestWithTableOperationErrorShouldLogException() {
        final String tableName = "fooBarTable";

        when(snmpClient.table(COMMUNIT_TARGET, tableName, SOME_OIDS))
                .thenAnswer(p -> {
                    throw new RuntimeException();
                });

        final String expectedLogDetails = SnmpClientRequestAggregator.Request
                .createLogDetails(COMMUNIT_TARGET, SOME_OIDS, Map.of("table_name", tableName))
                .toString();

        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            aggregator.createRequest(snmpClient).table(COMMUNIT_TARGET, tableName, SOME_OIDS);
        }

        final String expectedLogMessage = String.format("error invoking `table` operation, ignoring. %s", expectedLogDetails);
        loggerExt.getAppender().assertLog(
                SnmpClientRequestAggregator.class,
                Level.ERROR,
                (log) -> expectedLogMessage.equals(log.getMessage().getFormattedMessage()) &&
                        log.getThrown() instanceof RuntimeException
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void requestWithMultipleOperationsShouldAggregateResults() throws Exception {
        when(snmpClient.get(eq(COMMUNIT_TARGET), any())).thenReturn(
                Map.of("1", "one"),
                Map.of("2", "two")
        );

        when(snmpClient.walk(eq(COMMUNIT_TARGET), any())).thenReturn(
                Map.of("3", "three"),
                Map.of("4", "four")
        );

        when(snmpClient.table(eq(COMMUNIT_TARGET), anyString(), any())).thenReturn(
                Map.of("tableOne", List.of(Map.of("5", "five"))),
                Map.of("tableTwo", List.of(Map.of("6", "six")))
        );

        final AtomicReference<Map<String, Object>> resultRef = new AtomicReference<>();
        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            final SnmpClientRequestAggregator.Request request = aggregator.createRequest(snmpClient);
            request.get(COMMUNIT_TARGET, new OID[]{new OID("1")});
            request.get(COMMUNIT_TARGET, new OID[]{new OID("2")});
            request.walk(COMMUNIT_TARGET, new OID("3"));
            request.walk(COMMUNIT_TARGET, new OID("4"));
            request.table(COMMUNIT_TARGET, "tableOne", new OID[]{new OID("5")});
            request.table(COMMUNIT_TARGET, "tableTwo", new OID[]{new OID("6")});
            request.getResultAsync(resultRef::set).get(RESULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        }

        final Map<String, Object> result = resultRef.get();
        assertNotNull(result);

        assertEquals("one", result.get("1"));
        assertEquals("two", result.get("2"));
        assertEquals("three", result.get("3"));
        assertEquals("four", result.get("4"));

        final List<Map<String, String>> tableOne = (List<Map<String, String>>) result.get("tableOne");
        assertNotNull(tableOne);
        assertEquals(1, tableOne.size());
        assertEquals("five", tableOne.get(0).get("5"));

        final List<Map<String, String>> tableTwo = (List<Map<String, String>>) result.get("tableTwo");
        assertNotNull(tableTwo);
        assertEquals(1, tableTwo.size());
        assertEquals("six", tableTwo.get(0).get("6"));
    }

    @Test
    void requestWithMultipleOperationsShouldAggregateResultsEvenIfOneFail() throws Exception {
        when(snmpClient.get(COMMUNIT_TARGET, SOME_OIDS))
                .thenReturn(Map.of("get", "foo"));

        when(snmpClient.walk(eq(COMMUNIT_TARGET), any()))
                .thenReturn(Map.of("walk", "bar"));

        when(snmpClient.table(eq(COMMUNIT_TARGET), anyString(), any()))
                .thenAnswer(p -> {
                    throw new UnknownHostException();
                });

        final AtomicReference<Map<String, Object>> resultRef = new AtomicReference<>();
        try (SnmpClientRequestAggregator aggregator = createAggregator()) {
            final SnmpClientRequestAggregator.Request request = aggregator.createRequest(snmpClient);
            request.get(COMMUNIT_TARGET, SOME_OIDS);
            request.table(COMMUNIT_TARGET, "tableOne", SOME_OIDS);
            request.walk(COMMUNIT_TARGET, new OID("2"));
            request.getResultAsync(resultRef::set).get(RESULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        }

        final Map<String, Object> result = resultRef.get();
        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("foo", result.get("get"));
        assertEquals("bar", result.get("walk"));

        final String expectedLogDetails = SnmpClientRequestAggregator.Request
                .createLogDetails(COMMUNIT_TARGET, SOME_OIDS, Map.of("table_name", "tableOne"))
                .toString();

        final String expectedLogMessage = String.format("error invoking `table` operation, ignoring. %s", expectedLogDetails);
        loggerExt.getAppender().assertLogWithMessage(
                SnmpClientRequestAggregator.class,
                Level.ERROR,
                expectedLogMessage
        );
    }

    SnmpClientRequestAggregator createAggregator() {
        return new SnmpClientRequestAggregator(THREADS, THREAD_POOL_NAME);
    }
}