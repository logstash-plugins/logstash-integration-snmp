package org.logstash.snmp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.logstash.snmp.mib.MibManager;
import org.mockito.ArgumentCaptor;
import org.snmp4j.CommandResponder;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivacyProtocol;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.TSM;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.security.UsmUserEntry;
import org.snmp4j.smi.Counter32;
import org.snmp4j.smi.Counter64;
import org.snmp4j.smi.Gauge32;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.IpAddress;
import org.snmp4j.smi.Null;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Opaque;
import org.snmp4j.smi.SMIConstants;
import org.snmp4j.smi.TimeTicks;
import org.snmp4j.smi.UnsignedInteger32;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.transport.TLSTM;
import org.snmp4j.util.TableEvent;
import org.snmp4j.util.TableUtils;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SnmpClientTest {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 1061;
    private static final String LOCAL_ENGINE_ID = new String(MPv3.createLocalEngineID());
    private static final UsmUser USER = new UsmUser(
            new OctetString("admin"),
            AuthMD5.ID,
            new OctetString("auth-pass"),
            SnmpConstants.usmDESPrivProtocol,
            new OctetString("priv-pass")
    );

    private final MibManager mibManager = mock(MibManager.class);

    @Test
    void shouldAddSnmpMessageDispatcherProcessingModels() throws IOException {
        try (final SnmpClient client = createClient()) {
            final MessageDispatcher dispatcher = client.getSnmp().getMessageDispatcher();
            assertNotNull(dispatcher.getMessageProcessingModel(MPv1.ID));
            assertNotNull(dispatcher.getMessageProcessingModel(MPv2c.ID));
            assertNotNull(dispatcher.getMessageProcessingModel(MPv3.ID));
        }
    }

    @Test
    void shouldAddSnmpMultipleProtocolsTransportMappings() throws IOException {
        try (final SnmpClient client = createClient(Set.of("tcp", "udp", "tls"))) {
            @SuppressWarnings("rawtypes") final TransportMapping[] mappings = client.getSnmp()
                    .getMessageDispatcher()
                    .getTransportMappings()
                    .toArray(new TransportMapping[0]);

            assertEquals(3, mappings.length);
            assertTrue(Arrays.stream(mappings).anyMatch(p -> p instanceof DefaultTcpTransportMapping));
            assertTrue(Arrays.stream(mappings).anyMatch(p -> p instanceof DefaultUdpTransportMapping));
            assertTrue(Arrays.stream(mappings).anyMatch(p -> p instanceof TLSTM));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"tcp", "udp", "tls"})
    void shouldAddSnmpSingleProtocolTransportMapping(String protocol) throws IOException {
        try (final SnmpClient client = createClient(Set.of(protocol))) {
            @SuppressWarnings("rawtypes") final TransportMapping[] mappings = client.getSnmp()
                    .getMessageDispatcher()
                    .getTransportMappings()
                    .toArray(new TransportMapping[0]);

            assertEquals(1, mappings.length);
            switch (protocol) {
                case "tcp":
                    assertInstanceOf(DefaultTcpTransportMapping.class, mappings[0]);
                    break;
                case "udp":
                    assertInstanceOf(DefaultUdpTransportMapping.class, mappings[0]);
                    break;
                case "tls":
                    assertInstanceOf(TLSTM.class, mappings[0]);
                    break;
                default:
                    fail("Invalid protocol " + protocol);
            }
        }
    }

    @Test
    void shouldSetSnmpMPv3LocalEngineId() throws IOException {
        try (final SnmpClient client = createClient()) {
            final MPv3 mpv3 = (MPv3) client.getSnmp().getMessageProcessingModel(MPv3.ID);
            assertNotNull(mpv3);
            assertArrayEquals(LOCAL_ENGINE_ID.getBytes(), mpv3.getLocalEngineID());
        }
    }

    @Test
    void shouldAddSnmpUsmUsers() throws IOException {
        final Integer32 usmModelId = new Integer32(3);
        try (final SnmpClient client = createClient()) {
            final USM usm = client.getSnmp().getUSM();
            assertNotNull(usm);
            final UsmUserEntry user = usm.getUser(new OctetString(), USER.getSecurityName());

            assertNotNull(user);
            assertEquals(USER, user.getUsmUser());
        }
    }

    @Test
    void shouldAddSnmpTsmSecurityModel() throws IOException {
        final Integer32 tsmModelId = new Integer32(4);
        try (final SnmpClient ignore = createClient()) {
            final SecurityModel tsmModel = SecurityModels
                    .getInstance()
                    .getSecurityModel(tsmModelId);

            assertNotNull(tsmModel);
            assertInstanceOf(TSM.class, tsmModel);
        }
    }

    @Test
    void shouldAddSnmpPriv3DESProtocol() throws IOException {
        try (final SnmpClient ignore = createClient()) {
            final PrivacyProtocol protocol = SecurityProtocols.getInstance().getPrivacyProtocol(Priv3DES.ID);
            assertNotNull(protocol);
        }
    }

    @Test
    void listenShouldInvokeSnmpListen() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());

            when(client.getSnmp())
                    .thenReturn(snmp);

            client.listen();

            verify(snmp).listen();
        }
    }

    @Test
    void listenWithCommandResponderShouldAddResponderAndBlock() throws Exception {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());

            when(client.getSnmp())
                    .thenReturn(snmp);

            final CountDownLatch snmpListenLatch = new CountDownLatch(1);
            doAnswer(ignore -> {
                snmpListenLatch.countDown();
                return null;
            }).when(snmp).listen();

            final CommandResponder commandResponder = event -> {/*Nothing to do here*/};
            final Thread thread = new Thread(() -> {
                try {
                    client.listen(commandResponder);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });

            thread.start();

            // Allow the client to start listening
            final boolean listenInvoked = snmpListenLatch.await(500, TimeUnit.MILLISECONDS);
            assertTrue(listenInvoked);

            // Check if the command responder was added
            verify(snmp).addCommandResponder(commandResponder);
        }
    }

    @Test
    void getShouldProperlyCreateV1Pdu() throws IOException {
        try (final SnmpClient client = createClient()) {
            assertGetPdu(
                    client,
                    "1",
                    PDU.class,
                    new OID[]{new OID("1"), new OID("1.2.3")}
            );
        }
    }

    @Test
    void getShouldProperlyCreateV2cPdu() throws IOException {
        try (final SnmpClient client = createClient()) {
            assertGetPdu(
                    client,
                    "2c",
                    PDU.class,
                    new OID[]{new OID("1"), new OID("1.2.3")}
            );
        }
    }

    @Test
    void getShouldProperlyCreateV3Pdu() throws IOException {
        try (final SnmpClient client = createClient()) {
            assertGetPdu(
                    client,
                    "3",
                    ScopedPDU.class,
                    new OID[]{new OID("1"), new OID("1.2.3")}
            );
        }
    }

    @Test
    void getWithContextEngineIdAndNameShouldProperlyCreateV3Pdu() throws IOException {
        final OctetString contextEngineId = new OctetString("foo");
        final OctetString contextName = new OctetString("bar");

        try (final SnmpClient client = createClientBuilder(Set.of("udp"))
                .setContextEngineId(contextEngineId.toString())
                .setContextName(contextName.toString())
                .build()) {

            final ScopedPDU pdu = (ScopedPDU) assertGetPdu(
                    client,
                    "3",
                    ScopedPDU.class,
                    new OID[]{new OID("1.2"), new OID("1.2.3.4.5")}
            );

            assertEquals(contextEngineId, pdu.getContextEngineID());
            assertEquals(contextName, pdu.getContextName());
        }
    }

    private PDU assertGetPdu(SnmpClient client, String targetVersion, Class<?> expectedPduClass, OID[] expectedBindings) throws IOException {
        final SnmpClient clientSpy = spy(client);
        final Snmp snmp = spy(clientSpy.getSnmp());

        when(clientSpy.getSnmp())
                .thenReturn(snmp);

        final ArgumentCaptor<PDU> pduCaptor = ArgumentCaptor.forClass(PDU.class);

        doReturn(null)
                .when(snmp)
                .send(pduCaptor.capture(), any(Target.class));

        final Target v3Target = createTarget(clientSpy, HOST, targetVersion);
        clientSpy.get(v3Target, expectedBindings);

        final PDU sentPdu = pduCaptor.getValue();
        assertEquals(PDU.GET, sentPdu.getType());
        assertInstanceOf(expectedPduClass, sentPdu);

        final VariableBinding[] expectedVariableBindings = VariableBinding
                .createFromOIDs(expectedBindings);


        assertArrayEquals(expectedVariableBindings, sentPdu.getVariableBindings().toArray(new VariableBinding[0]));

        return sentPdu;
    }

    @Test
    void getWithNullResponseShouldReturnEmpty() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());

            when(client.getSnmp())
                    .thenReturn(snmp);

            doReturn(null)
                    .when(snmp)
                    .send(any(PDU.class), any(Target.class));

            final Map<String, Object> response = client
                    .get(mock(Target.class), new OID[]{new OID("1")});

            assertTrue(response.isEmpty());
        }
    }

    @Test
    void getWithErrorResponseShouldThrow() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());
            final ResponseEvent responseEvent = mock(ResponseEvent.class);

            when(client.getSnmp())
                    .thenReturn(snmp);

            when(responseEvent.getError())
                    .thenReturn(new IOException("connection reset"));

            doReturn(responseEvent)
                    .when(snmp)
                    .send(any(PDU.class), any(Target.class));

            final Target target = createTarget(client, "tcp:192.168.1.1/161", "3");
            final OID[] oids = new OID[]{new OID("1")};
            final SnmpClientException exception = assertThrows(
                    SnmpClientException.class,
                    () -> client.get(target, oids)
            );

            assertEquals(
                    "error sending snmp get request to target 192.168.1.1/161: connection reset",
                    exception.getMessage()
            );
        }
    }

    @Test
    void getWithNullResponseShouldThrowTimeoutException() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());
            final ResponseEvent responseEvent = mock(ResponseEvent.class);

            when(client.getSnmp())
                    .thenReturn(snmp);

            doReturn(responseEvent)
                    .when(snmp)
                    .send(any(PDU.class), any(Target.class));

            final Target target = createTarget(client, "tcp:192.2.1.1/161", "3");
            final OID[] oids = new OID[]{new OID("1")};

            final SnmpClientException exception = assertThrows(
                    SnmpClientException.class,
                    () -> client.get(target, oids)
            );

            assertEquals(
                    "timeout sending snmp get request to target 192.2.1.1/161",
                    exception.getMessage()
            );
        }
    }

    @Test
    void getWithResponseShouldReturnProperlyMappedFields() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());

            when(client.getSnmp())
                    .thenReturn(snmp);

            final ResponseEvent responseEvent = mock(ResponseEvent.class);
            final List<VariableBinding> responseVariables = List.of(
                    new VariableBinding(new OID("1.1"), new OctetString("foo")),
                    new VariableBinding(new OID("1.2"), new OctetString("bar"))
            );

            doReturn(new PDU(PDU.RESPONSE, responseVariables))
                    .when(responseEvent)
                    .getResponse();

            doReturn(responseEvent)
                    .when(snmp)
                    .send(any(PDU.class), any(Target.class));

            when(mibManager.map(any(OID.class)))
                    .thenReturn("iso.foo", "iso.bar");

            final Target target = createTarget(client, "tcp:192.2.1.1/161", "3");
            final Map<String, Object> response = client.get(target, new OID[]{new OID("1.1"), new OID("1.2")});

            assertFalse(response.isEmpty());
            responseVariables.forEach(binding -> verify(client).coerceVariable(binding.getVariable()));
            assertEquals("foo", response.get("iso.foo"));
            assertEquals("bar", response.get("iso.bar"));
        }
    }

    @Test
    void walkWithNullOrEmptyResponseShouldReturnEmpty() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final TreeUtils treeUtils = mock(TreeUtils.class);

            when(client.createGetTreeUtils())
                    .thenReturn(treeUtils);

            doReturn(null, List.of())
                    .when(treeUtils)
                    .getSubtree(any(Target.class), any(OID.class));

            final Target target = createTarget(client, HOST, "1");
            assertTrue(client.walk(target, new OID("1")).isEmpty());
            assertTrue(client.walk(target, new OID("2")).isEmpty());
        }
    }

    @Test
    void walkWithErrorResponseShouldThrow() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final TreeUtils treeUtils = mock(TreeUtils.class);

            when(client.createGetTreeUtils())
                    .thenReturn(treeUtils);

            final TreeEvent event = mock(TreeEvent.class);

            when(event.isError())
                    .thenReturn(true);

            when(event.getErrorMessage())
                    .thenReturn("unknown error");

            doReturn(List.of(event))
                    .when(treeUtils)
                    .getSubtree(any(Target.class), any(OID.class));

            final Target target = createTarget(client, "tcp:192.168.1.1/161", "3");
            final OID oid = new OID("1.2.3");
            final SnmpClientException exception = assertThrows(
                    SnmpClientException.class,
                    () -> client.walk(target, oid)
            );

            assertEquals(
                    "error sending snmp walk request to target 192.168.1.1/161: unknown error",
                    exception.getMessage()
            );
        }
    }

    @Test
    void walkWithResponseShouldReturnProperlyMappedFields() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final TreeUtils treeUtils = mock(TreeUtils.class);

            when(client.createGetTreeUtils())
                    .thenReturn(treeUtils);

            final TreeEvent event = mock(TreeEvent.class);
            final List<VariableBinding> responseVariables = List.of(
                    new VariableBinding(new OID("1.1"), new OctetString("foo")),
                    new VariableBinding(new OID("1.2"), new OctetString("bar"))
            );

            when(event.getVariableBindings())
                    .thenReturn(responseVariables.toArray(new VariableBinding[0]));

            doReturn(List.of(event))
                    .when(treeUtils)
                    .getSubtree(any(Target.class), any(OID.class));

            when(mibManager.map(any(OID.class)))
                    .thenReturn("iso.foo", "iso.bar");

            final Target target = createTarget(client, "tcp:192.2.1.1/161", "3");
            final Map<String, Object> response = client.walk(target, new OID("1"));

            assertFalse(response.isEmpty());
            responseVariables.forEach(binding -> verify(client).coerceVariable(binding.getVariable()));
            assertEquals("foo", response.get("iso.foo"));
            assertEquals("bar", response.get("iso.bar"));
        }
    }

    @Test
    void tableWithNullOrEmptyResponseShouldReturnEmpty() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final TableUtils tableUtils = mock(TableUtils.class);

            when(client.createGetTableUtils())
                    .thenReturn(tableUtils);

            doReturn(null, List.of())
                    .when(tableUtils)
                    .getTable(any(Target.class), any(OID[].class), isNull(), isNull());

            final Target target = createTarget(client, HOST, "1");
            assertTrue(client.table(target, "fooTable", List.of(new OID("1"))).isEmpty());
            assertTrue(client.table(target, "barTable", List.of(new OID("2"))).isEmpty());
        }
    }

    @Test
    void tableWithErrorResponseShouldThrow() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final TableUtils tableUtils = mock(TableUtils.class);

            when(client.createGetTableUtils())
                    .thenReturn(tableUtils);

            final TableEvent event = mock(TableEvent.class);

            when(event.isError())
                    .thenReturn(true);

            when(event.getErrorMessage())
                    .thenReturn("unknown error");

            doReturn(List.of(event))
                    .when(tableUtils)
                    .getTable(any(Target.class), any(OID[].class), isNull(), isNull());

            final Target target = createTarget(client, "tcp:192.168.1.1/161", "3");
            final List<OID> oids = List.of(new OID("1.2.3"));

            final SnmpClientException exception = assertThrows(
                    SnmpClientException.class,
                    () -> client.table(target, "fooTable", oids)
            );

            assertEquals(
                    "error sending snmp table request to target 192.168.1.1/161: unknown error",
                    exception.getMessage()
            );
        }
    }

    @Test
    void tableWithResponseShouldReturnProperlyMappedFields() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final TableUtils tableUtils = mock(TableUtils.class);
            when(client.createGetTableUtils()).thenReturn(tableUtils);

            final TableEvent eventOne = mock(TableEvent.class);
            final TableEvent eventTwo = mock(TableEvent.class);
            final VariableBinding[] responseVariables = new VariableBinding[]{
                    new VariableBinding(new OID("1.1"), new OctetString("foo")),
                    new VariableBinding(new OID("1.2"), new OctetString("bar"))
            };

            when(eventOne.getIndex()).thenReturn(new OID("1"));
            when(eventTwo.getIndex()).thenReturn(new OID("2"));

            when(eventOne.getColumns()).thenReturn(responseVariables);
            when(eventTwo.getColumns()).thenReturn(responseVariables);

            doReturn(List.of(eventOne, eventTwo))
                    .when(tableUtils)
                    .getTable(any(Target.class), any(OID[].class), isNull(), isNull());

            when(mibManager.map(any(OID.class)))
                    .thenReturn("one.foo", "one.bar", "two.foo", "two.bar");

            final String tableName = "fooBarTable";
            final Target target = createTarget(client, "tcp:192.2.1.1/161", "3");

            final var response = client.table(target, tableName, List.of(new OID("1")));
            assertFalse(response.isEmpty());
            Arrays.stream(responseVariables)
                    .forEach(binding -> verify(client, times(2)).coerceVariable(binding.getVariable()));


            final List<Map<String, Object>> fooBarTable = response.get(tableName);
            assertEquals(2, fooBarTable.size());

            final Map<String, Object> mappedEventOne = fooBarTable.get(0);
            assertEquals("1", mappedEventOne.get("index"));
            assertEquals("foo", mappedEventOne.get("one.foo"));
            assertEquals("bar", mappedEventOne.get("one.bar"));

            final Map<String, Object> mappedEventTwo = fooBarTable.get(1);
            assertEquals("2", mappedEventTwo.get("index"));
            assertEquals("foo", mappedEventTwo.get("two.foo"));
            assertEquals("bar", mappedEventTwo.get("two.bar"));
        }
    }

    @Test
    void coerceVariableShouldReturnErrorStringsWhenIsException() throws IOException {
        try (SnmpClient client = createClient()) {
            assertEquals("error: no such instance currently exists at this OID",
                    client.coerceVariable(new Null(SMIConstants.EXCEPTION_NO_SUCH_INSTANCE)));

            assertEquals("error: no such object currently exists at this OID",
                    client.coerceVariable(new Null(SMIConstants.EXCEPTION_NO_SUCH_OBJECT)));

            assertEquals("end of MIB view",
                    client.coerceVariable(new Null(SMIConstants.EXCEPTION_END_OF_MIB_VIEW)));
        }
    }

    @Test
    void coerceVariableShouldReturnNullWordWhenSyntaxIsAsnNull() throws IOException {
        try (SnmpClient client = createClient()) {
            assertEquals("null", client.coerceVariable(new Null()));
        }
    }

    @Test
    void coerceVariableShouldReturnParsedValueWhenVarIsAssignableFromNumber() throws IOException {
        try (SnmpClient client = createClient()) {
            assertEquals(1L, client.coerceVariable(new Counter32(1L)));
            assertEquals(2L, client.coerceVariable(new Counter64(2L)));
            assertEquals(3L, client.coerceVariable(new Gauge32(3L)));
            assertEquals(4L, client.coerceVariable(new TimeTicks(4L)));
            assertEquals(5L, client.coerceVariable(new UnsignedInteger32(5L)));
            assertEquals(1, client.coerceVariable(new Integer32(1)));
        }
    }

    @Test
    void coerceVariableShouldReturnStringValueWhenVarIsNotAssignableFromNumber() throws IOException {
        try (SnmpClient client = createClient()) {
            assertEquals("0.0.0.0", client.coerceVariable(new IpAddress()));
            assertEquals("foo", client.coerceVariable(new OctetString("foo")));
            assertEquals("62:61:72", client.coerceVariable(new Opaque("bar".getBytes())));
        }
    }

    @Test
    void coerceVariableShouldReturnFallbackValueWhenToStringFails() throws IOException {
        try (SnmpClient client = createClient()) {
            final OctetString erroredVariable = new OctetString() {
                @Override
                public String toString() {
                    throw new RuntimeException("unknown error");
                }
            };

            assertEquals(
                    "error: unable to read variable value. Syntax: 4 (OCTET STRING)",
                    client.coerceVariable(erroredVariable)
            );
        }
    }

    private Target createTarget(SnmpClient client, String address, String version) {
        return client.createTarget(
                address,
                version,
                1,
                1000,
                "default",
                "guest",
                "noauthnopriv"
        );
    }

    private SnmpClient createClient() throws IOException {
        return createClient(Set.of("udp"));
    }

    private SnmpClient createClient(Set<String> protocols) throws IOException {
        return createClientBuilder(protocols).build();
    }

    private SnmpClientBuilder createClientBuilder(Set<String> protocols) {
        return SnmpClient.builder(mibManager, protocols, PORT)
                .setThreadPoolName("FooBarWorker")
                .setThreadPoolSize(1)
                .setLocalEngineId(LOCAL_ENGINE_ID)
                .addUsmUser(
                        USER.getSecurityName().toString(),
                        "md5",
                        USER.getAuthenticationPassphrase().toString(),
                        "des",
                        USER.getPrivacyPassphrase().toString());
    }
}