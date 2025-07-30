package org.logstash.snmp;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.logstash.snmp.mib.MibManager;
import org.logstash.snmp.trap.SnmpTrapMessage;
import org.mockito.ArgumentCaptor;
import org.mockito.stubbing.Answer;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthHMAC192SHA256;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivacyProtocol;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.TSM;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.security.UsmUserEntry;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.Counter32;
import org.snmp4j.smi.Counter64;
import org.snmp4j.smi.Gauge32;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.IpAddress;
import org.snmp4j.smi.Null;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Opaque;
import org.snmp4j.smi.SMIConstants;
import org.snmp4j.smi.TimeTicks;
import org.snmp4j.smi.UdpAddress;
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
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SnmpClientTest {
    private static final Duration CLIENT_CLOSE_TIMEOUT = Duration.ofSeconds(5);
    private static final String HOST_ADDRESS = "localhost/161";
    private static final int PORT = 1069;
    private static final String LOCAL_ENGINE_ID = new String(MPv3.createLocalEngineID());
    private static final UsmUser USER = new UsmUser(
            new OctetString("admin"),
            AuthMD5.ID,
            new OctetString("auth-pass"),
            SnmpConstants.usmDESPrivProtocol,
            new OctetString("priv-pass")
    );
    public static final UdpAddress TRAP_PEER_ADDRESS = new UdpAddress("10.1.2.3/161");
    public static final String TRAP_SECURITY_NAME = "public";

    private final MibManager mibManager = mock(MibManager.class);

    @RegisterExtension
    LoggerAppenderExtension loggerExt = new LoggerAppenderExtension(LogManager.getLogger(SnmpClient.class));

    @Test
    void shouldAddByDefaultAllSnmpMessageDispatcherProcessingModels() throws IOException {
        try (final SnmpClient client = createClient()) {
            final MessageDispatcher dispatcher = client.getSnmp().getMessageDispatcher();
            assertNotNull(dispatcher.getMessageProcessingModel(MPv1.ID));
            assertNotNull(dispatcher.getMessageProcessingModel(MPv2c.ID));
            assertNotNull(dispatcher.getMessageProcessingModel(MPv3.ID));
        }
    }

    @Test
    void shouldAddOnlySupportedSnmpMessageDispatcherProcessingModels() throws IOException {
        final SnmpClientBuilder builder = createClientBuilder(Set.of("udp"))
                .setSupportedVersions(Set.of("2c", "3"));

        try (final SnmpClient client = builder.build()) {
            final MessageDispatcher dispatcher = client.getSnmp().getMessageDispatcher();
            assertNull(dispatcher.getMessageProcessingModel(MPv1.ID));
            assertNotNull(dispatcher.getMessageProcessingModel(MPv2c.ID));
            assertNotNull(dispatcher.getMessageProcessingModel(MPv3.ID));
        }
    }

    @Test
    void shouldAddTsmWhenVersion3IsEnabled() throws IOException {
        final SnmpClientBuilder builder = createClientBuilder(Set.of("udp"))
                .setSupportedVersions(Set.of("3"));

        final Integer32 tsmModelId = new Integer32(SecurityModel.SECURITY_MODEL_TSM);
        SecurityModels.getInstance().removeSecurityModel(tsmModelId);

        try (final SnmpClient ignore = builder.build()) {
            final SecurityModel securityModel = SecurityModels
                    .getInstance()
                    .getSecurityModel(new Integer32(SecurityModel.SECURITY_MODEL_TSM));

            assertNotNull(securityModel);
        }
    }

    @Test
    void shouldNotAddTsmWhenVersion3IsDisabled() throws IOException {
        final SnmpClientBuilder builder = createClientBuilder(Set.of("udp"))
                .setSupportedVersions(Set.of("2c"));

        final Integer32 tsmModelId = new Integer32(SecurityModel.SECURITY_MODEL_TSM);
        SecurityModels.getInstance().removeSecurityModel(tsmModelId);

        try (final SnmpClient ignore = builder.build()) {
            final SecurityModel securityModel = SecurityModels
                    .getInstance()
                    .getSecurityModel(tsmModelId);

            assertNull(securityModel);
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
        try (final SnmpClient client = createClient()) {
            final USM usm = client.getSnmp().getUSM();
            assertNotNull(usm);
            final UsmUserEntry user = usm.getUser(new OctetString(), USER.getSecurityName());

            assertNotNull(user);
            assertEquals(USER, user.getUsmUser());
        }
    }

    @Test
    void shouldAddSnmpUsmUsersPerClientInstance() throws IOException {
        // This test ensures that two plugin instances (clients) aren't sharing the same USM
        // through the global security model repository. Otherwise, users with the same name
        // but different passwords would conflict.
        final OctetString securityName = new OctetString("root");
        try (final SnmpClient clientOne = creatEmptyClientBuilder(mibManager, Set.of("tcp"), PORT)
                .addUsmUser(securityName.toString(),
                        "hmac192sha256",
                        "client-one-pass",
                        "3des",
                        "client-one-pass",
                        "noAuthNoPriv"
                ).build();
             final SnmpClient clientTwo = creatEmptyClientBuilder(mibManager, Set.of("tcp"), PORT + 1)
                     .addUsmUser(securityName.toString(),
                             "md5",
                             "client-two-pass",
                             "des",
                             "client-two-pass",
                             "noAuthNoPriv"
                     ).build()
        ) {
            final USM usmClientOne = clientOne.getSnmp().getUSM();
            final USM usmClientTwo = clientTwo.getSnmp().getUSM();

            assertNotNull(usmClientOne);
            assertNotNull(usmClientTwo);
            assertNotEquals(usmClientOne, usmClientTwo);

            final UsmUser userClientOne = usmClientOne.getUser(new OctetString(), securityName).getUsmUser();
            assertEquals(securityName, userClientOne.getSecurityName());
            assertEquals(AuthHMAC192SHA256.ID, userClientOne.getAuthenticationProtocol());
            assertEquals(new OctetString("client-one-pass"), userClientOne.getAuthenticationPassphrase());
            assertEquals(SnmpConstants.usm3DESEDEPrivProtocol, userClientOne.getPrivacyProtocol());
            assertEquals(new OctetString("client-one-pass"), userClientOne.getPrivacyPassphrase());

            final UsmUser userClientTwo = usmClientTwo.getUser(new OctetString(), securityName).getUsmUser();
            assertEquals(securityName, userClientTwo.getSecurityName());
            assertEquals(AuthMD5.ID, userClientTwo.getAuthenticationProtocol());
            assertEquals(new OctetString("client-two-pass"), userClientTwo.getAuthenticationPassphrase());
            assertEquals(SnmpConstants.usmDESPrivProtocol, userClientTwo.getPrivacyProtocol());
            assertEquals(new OctetString("client-two-pass"), userClientTwo.getPrivacyPassphrase());
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
    void shouldFailToSetSupportedVersionsEmpty() {
        final IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> createClientBuilder(Set.of("udp")).setSupportedVersions(Set.of())
        );

        assertEquals("at least one SNMP version must be supported", exception.getMessage());
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

    private PDU assertGetPdu(SnmpClient client, String targetVersion, Class<?> expectedPduClass, OID[] expectedBindings) throws IOException {
        final SnmpClient clientSpy = spy(client);
        final Snmp snmp = spy(clientSpy.getSnmp());

        when(clientSpy.getSnmp())
                .thenReturn(snmp);

        final ArgumentCaptor<PDU> pduCaptor = ArgumentCaptor.forClass(PDU.class);

        doReturn(null)
                .when(snmp)
                .send(pduCaptor.capture(), any());

        final Target<Address> v3Target = createTarget(clientSpy, HOST_ADDRESS, targetVersion);
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
                    .send(any(PDU.class), any());

            final Map<String, Object> response = client
                    .get(mock(), new OID[]{new OID("1")});

            assertTrue(response.isEmpty());
        }
    }

    @Test
    void getWithErrorResponseShouldThrow() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());
            final ResponseEvent<Address> responseEvent = mock();

            when(client.getSnmp())
                    .thenReturn(snmp);

            when(responseEvent.getError())
                    .thenReturn(new IOException("connection reset"));

            doReturn(responseEvent)
                    .when(snmp)
                    .send(any(PDU.class), any());

            final Target<Address> target = createTarget(client, "tcp:192.168.1.1/161", "3");
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
            final ResponseEvent<Address> responseEvent = mock();

            when(client.getSnmp())
                    .thenReturn(snmp);

            doReturn(responseEvent)
                    .when(snmp)
                    .send(any(PDU.class), any());

            final Target<Address> target = createTarget(client, "tcp:192.2.1.1/161", "3");
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

            final ResponseEvent<Address> responseEvent = mock();
            final List<VariableBinding> responseVariables = List.of(
                    new VariableBinding(new OID("1.1"), new OctetString("foo")),
                    new VariableBinding(new OID("1.2"), new OctetString("bar"))
            );

            doReturn(new PDU(PDU.RESPONSE, responseVariables))
                    .when(responseEvent)
                    .getResponse();

            doReturn(responseEvent)
                    .when(snmp)
                    .send(any(PDU.class), any());

            when(mibManager.map(any(OID.class)))
                    .thenReturn("iso.foo", "iso.bar");

            final Target<Address> target = createTarget(client, "tcp:192.2.1.1/161", "3");
            final Map<String, Object> response = client.get(target, new OID[]{new OID("1.1"), new OID("1.2")});

            assertFalse(response.isEmpty());
            responseVariables.forEach(binding -> verify(client).coerceVariable(binding.getVariable()));
            assertEquals("foo", response.get("iso.foo"));
            assertEquals("bar", response.get("iso.bar"));
        }
    }

    @Test
    void getWithUnsupportedTargetVersionShouldThrow() throws IOException {
        try (final SnmpClient client = createClientBuilder(Set.of("udp"))
                .setSupportedVersions(Set.of("2c"))
                .build()) {

            final Target<Address> target = createTarget(client, "tcp:192.2.1.1/161", "3");

            final SnmpClientException exception = assertThrows(
                    SnmpClientException.class,
                    () -> client.get(target, new OID[]{new OID("1.1")})
            );

            assertEquals("SNMP version `3` is disabled", exception.getMessage());
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
                    .getSubtree(any(), any(OID.class));

            final Target<Address> target = createTarget(client, HOST_ADDRESS, "1");
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
                    .getSubtree(any(), any(OID.class));

            final Target<Address> target = createTarget(client, "tcp:192.168.1.1/161", "3");
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
                    .getSubtree(any(), any(OID.class));

            when(mibManager.map(any(OID.class)))
                    .thenReturn("iso.foo", "iso.bar");

            final Target<Address> target = createTarget(client, "tcp:192.2.1.1/161", "3");
            final Map<String, Object> response = client.walk(target, new OID("1"));

            assertFalse(response.isEmpty());
            responseVariables.forEach(binding -> verify(client).coerceVariable(binding.getVariable()));
            assertEquals("foo", response.get("iso.foo"));
            assertEquals("bar", response.get("iso.bar"));
        }
    }

    @Test
    void walkWithUnsupportedTargetVersionShouldThrow() throws IOException {
        try (final SnmpClient client = createClientBuilder(Set.of("udp"))
                .setSupportedVersions(Set.of("2c"))
                .build()) {

            final Target<Address> target = createTarget(client, "tcp:192.2.1.1/161", "3");

            final SnmpClientException exception = assertThrows(
                    SnmpClientException.class,
                    () -> client.walk(target, new OID("1.1"))
            );

            assertEquals("SNMP version `3` is disabled", exception.getMessage());
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
                    .getTable(any(), any(OID[].class), isNull(), isNull());

            final Target<Address> target = createTarget(client, HOST_ADDRESS, "1");
            assertTrue(client.table(target, "fooTable", new OID[]{new OID("1")}).isEmpty());
            assertTrue(client.table(target, "barTable", new OID[]{new OID("2")}).isEmpty());
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
                    .getTable(any(), any(OID[].class), isNull(), isNull());

            final Target<Address> target = createTarget(client, "tcp:192.168.1.1/161", "3");
            final OID[] oids = {new OID("1.2.3")};

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
                    .getTable(any(), any(OID[].class), isNull(), isNull());

            when(mibManager.map(any(OID.class)))
                    .thenReturn("one.foo", "one.bar", "two.foo", "two.bar");

            final String tableName = "fooBarTable";
            final Target<Address> target = createTarget(client, "tcp:192.2.1.1/161", "3");

            final var response = client.table(target, tableName, new OID[]{new OID("1")});
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
    void tableShouldRemovedIndexFromVariableBindingOids() throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final TableUtils tableUtils = mock(TableUtils.class);
            when(client.createGetTableUtils()).thenReturn(tableUtils);

            final TableEvent eventOne = mock(TableEvent.class);
            when(eventOne.getColumns()).thenReturn(VariableBinding.createFromOIDs(
                    new OID[]{new OID("1.2.1"), new OID("1.3.1")}));
            when(eventOne.getIndex()).thenReturn(new OID("1"));

            final TableEvent eventTwo = mock(TableEvent.class);
            when(eventTwo.getColumns()).thenReturn(VariableBinding.createFromOIDs(
                    new OID[]{new OID("1.2.3.1.3"), new OID("1.1.3.1.3"), new OID("1.3.4.5")}));
            when(eventTwo.getIndex()).thenReturn(new OID("1.3"));

            doReturn(List.of(eventOne, eventTwo))
                    .when(tableUtils)
                    .getTable(any(), any(OID[].class), isNull(), isNull());

            // Return the OID passed as argument
            when(mibManager.map(any(OID.class)))
                    .thenAnswer((Answer<String>) invocation -> invocation.getArgument(0).toString());

            final List<Map<String, Object>> ifTable = client
                    .table(createTarget(client, "tcp:192.2.1.1/161", "3"), "ifTable", new OID[]{new OID("1")})
                    .get("ifTable");

            assertEquals(2, ifTable.size());

            final Map<String, Object> eventOneIdx = ifTable.stream()
                    .filter(p -> p.get("index").equals("1"))
                    .findFirst()
                    .orElseThrow();

            assertTrue(eventOneIdx.containsKey("1.2"));
            assertTrue(eventOneIdx.containsKey("1.3"));

            final Map<String, Object> eventTwoIdx = ifTable.stream()
                    .filter(p -> p.get("index").equals("1.3"))
                    .findFirst()
                    .orElseThrow();

            assertTrue(eventTwoIdx.containsKey("1.2.3"));
            assertTrue(eventTwoIdx.containsKey("1.1.3"));
            assertTrue(eventTwoIdx.containsKey("1.3.4.5"));
        }
    }

    @Test
    void tableWithUnsupportedTargetVersionShouldThrow() throws IOException {
        try (final SnmpClient client = createClientBuilder(Set.of("udp"))
                .setSupportedVersions(Set.of("1"))
                .build()) {

            final Target<Address> target = createTarget(client, "tcp:192.2.1.1/161", "2c");

            final SnmpClientException exception = assertThrows(
                    SnmpClientException.class,
                    () -> client.table(target, "FOO", new OID[]{new OID("1.1")})
            );

            assertEquals("SNMP version `2c` is disabled", exception.getMessage());
        }
    }

    @Test
    void coerceVariableShouldReturnErrorStringsWhenIsException() throws IOException {
        try (SnmpClient client = createClient()) {
            assertEquals("error: no such instance currently exists at this OID",
                    client.coerceVariable(new Null(SMIConstants.EXCEPTION_NO_SUCH_INSTANCE)));

            assertEquals("error: no such object currently exists at this OID",
                    client.coerceVariable(new Null(SMIConstants.EXCEPTION_NO_SUCH_OBJECT)));

            assertEquals("error: end of MIB view",
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

    @Test
    void coerceVariableShouldNotMapOidVariableValueByDefault() throws IOException {
        try (SnmpClient client = createClient()) {
            assertEquals("1.1", client.coerceVariable(new OID("1.1")));
            verifyNoInteractions(mibManager);
        }
    }

    @Test
    void coerceVariableShouldMapOidVariableValueWhenTrue() throws IOException {
        try (SnmpClient client = createClientBuilder(Set.of("udp"))
                .setMapOidVariableValues(true)
                .build()) {

            when(mibManager.map(any(OID.class)))
                    .thenReturn("foo.bar");

            assertEquals("foo.bar", client.coerceVariable(new OID("1.1")));
        }
    }

    @Test
    void trapShouldAddCommandResponderAndListen() throws Exception {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());
            when(client.getSnmp()).thenReturn(snmp);

            doNothing().when(snmp).listen();

            client.doTrap(new String[0], ignore -> {/*Empty*/}, new CountDownLatch(0));

            verify(snmp).addCommandResponder(any());
            verify(snmp).listen();
        }
    }

    @Test
    void trapShouldNotCallConsumerWhenCommunityIsNotAllowed() throws Exception {
        assertTrapConsumerWhenSecurityNameIs(SnmpConstants.version1, new String[]{"foo"}, "bar", 0, false);
    }

    @Test
    void trapShouldCallConsumerWhenCommunityIsAllowed() throws Exception {
        assertTrapConsumerWhenSecurityNameIs(SnmpConstants.version1, new String[]{"foo_community"}, "foo_community", 0, true);
    }

    @Test
    void trapShouldCallConsumerWhenCommunityIsEmpty() throws Exception {
        assertTrapConsumerWhenSecurityNameIs(SnmpConstants.version1, new String[0], "public", 0, true);
    }

    @Test
    void trapShouldNotCallConsumerWhenUserSecurityLevelIsNotAllowed() throws Exception {
        assertTrapConsumerWhenSecurityNameIs(SnmpConstants.version3, new String[]{"test"}, USER.getSecurityName().toString(), SecurityLevel.NOAUTH_NOPRIV, false);
    }

    @Test
    void trapShouldCallConsumerWhenUserSecurityLevelIsAllowed() throws Exception {
        assertTrapConsumerWhenSecurityNameIs(SnmpConstants.version3, new String[]{"test"}, USER.getSecurityName().toString(), SecurityLevel.AUTH_NOPRIV, true);
        assertTrapConsumerWhenSecurityNameIs(SnmpConstants.version3, new String[]{"test"}, USER.getSecurityName().toString(), SecurityLevel.AUTH_PRIV, true);
    }

    private void assertTrapConsumerWhenSecurityNameIs(
            int version,
            String[] allowedCommunities,
            String securityName,
            int securityLevel,
            boolean callExpected
    ) throws Exception {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());
            when(client.getSnmp()).thenReturn(snmp);
            doNothing().when(snmp).listen();

            final boolean[] called = new boolean[1];
            // Start traps client with non-blocking latch
            client.doTrap(allowedCommunities, ignore -> called[0] = true, new CountDownLatch(0));

            final CommandResponderEvent<Address> responderEvent = mock();
            when(responderEvent.getSecurityModel())
                    .thenReturn(version);
            when(responderEvent.getMessageProcessingModel())
                    .thenReturn(version);
            when(responderEvent.getSecurityName())
                    .thenReturn(securityName.getBytes());
            when(responderEvent.getSecurityLevel())
                    .thenReturn(securityLevel);
            when(responderEvent.getPDU())
                    .thenReturn(new PDUv1());

            // Simulates an incoming trap message
            snmp.processPdu(responderEvent);

            assertEquals(callExpected, called[0]);

            if (callExpected) {
                loggerExt.getAppender().assertNoLogWithFormat(
                        SnmpClient.class,
                        Level.DEBUG,
                        "Received trap message with unknown community: '{}'. Skipping"
                );
            } else {
                if (version < SnmpConstants.version3) {
                    loggerExt.getAppender().assertLogWithMessage(
                            SnmpClient.class,
                            Level.DEBUG,
                            String.format("Received trap message with unknown community: '%s'. Skipping", securityName)
                    );
                } else {
                    loggerExt.getAppender().assertLogWithFormat(
                            SnmpClient.class,
                            Level.DEBUG,
                            "Unsupported security level {} by user {}, minimum security level is {}. Skipping"
                    );

                }
            }
        }
    }

    @Test
    void trapShouldProperlyCreateTrapMessageFormattedBindings() throws IOException {
        final PDUv1 pdUv1 = new PDUv1();
        pdUv1.setType(PDU.V1TRAP);
        pdUv1.setVariableBindings(List.of(
                new VariableBinding(new OID("1.1"), new OctetString("foo")),
                new VariableBinding(new OID("1.2"), new OctetString("bar")),
                new VariableBinding(new OID("1.3"), new OctetString("dummy"))
        ));

        when(mibManager.map(any(OID.class)))
                .thenReturn("iso.foo", "iso.bar", "iso.dummy");

        final SnmpTrapMessage snmpTrapMessage = executeTrapAndGetProducedSnmpTrapMessage(1, pdUv1, TRAP_SECURITY_NAME, SecurityLevel.NOAUTH_NOPRIV);

        final Map<String, Object> formattedVariableBindings = snmpTrapMessage.getFormattedVariableBindings();
        assertEquals("foo", formattedVariableBindings.get("iso.foo"));
        assertEquals("bar", formattedVariableBindings.get("iso.bar"));
        assertEquals("dummy", formattedVariableBindings.get("iso.dummy"));
    }

    @Test
    void trapShouldProperlyCreateV1TrapMessage() throws IOException {
        final PDUv1 pdUv1 = new PDUv1();
        pdUv1.setType(PDU.V1TRAP);
        pdUv1.setRequestID(new Integer32(123));
        pdUv1.setEnterprise(new OID("1.2.3.4.5"));
        pdUv1.setAgentAddress(new IpAddress("123.123.123.123"));
        pdUv1.setGenericTrap(100);
        pdUv1.setSpecificTrap(200);
        pdUv1.setTimestamp(300);
        pdUv1.setVariableBindings(List.of(
                new VariableBinding(new OID("1.1"), new OctetString("foo")),
                new VariableBinding(new OID("1.2"), new OctetString("bar"))
        ));

        when(mibManager.map(any(OID.class)))
                .thenReturn("iso.foo", "iso.bar");

        final SnmpTrapMessage snmpTrapMessage = executeTrapAndGetProducedSnmpTrapMessage(SnmpConstants.version1, pdUv1, TRAP_SECURITY_NAME, SecurityLevel.NOAUTH_NOPRIV);
        assertEquals(SnmpConstants.version1, snmpTrapMessage.getVersion());
        assertEquals(TRAP_SECURITY_NAME, snmpTrapMessage.getSecurityNameString());
        assertEquals(TRAP_PEER_ADDRESS.getInetAddress().getHostAddress(), snmpTrapMessage.getPeerIpAddress());

        final Map<String, Object> trapEvent = snmpTrapMessage.getTrapEvent();
        assertEquals("1", trapEvent.remove("version"));
        assertEquals(PDU.getTypeString(pdUv1.getType()), trapEvent.remove("type"));

        assertEquals(TRAP_SECURITY_NAME, trapEvent.remove("community"));
        assertEquals(pdUv1.getEnterprise().toString(), trapEvent.remove("enterprise"));
        assertEquals(pdUv1.getAgentAddress().toString(), trapEvent.remove("agent_addr"));
        assertEquals(pdUv1.getGenericTrap(), trapEvent.remove("generic_trap"));
        assertEquals(pdUv1.getSpecificTrap(), trapEvent.remove("specific_trap"));
        assertEquals(pdUv1.getTimestamp(), trapEvent.remove("timestamp"));

        @SuppressWarnings("unchecked") final Map<String, Object> variableBindings = (Map<String, Object>) trapEvent.remove("variable_bindings");
        pdUv1.getVariableBindings().forEach(binding -> assertEquals(
                binding.getVariable().toString(),
                variableBindings.remove(binding.getOid().toString()))
        );

        // No extra trap event properties
        assertTrue(trapEvent.isEmpty());

        // No extra variable bindings
        assertTrue(variableBindings.isEmpty());

        final Map<String, Object> formattedVariableBindings = snmpTrapMessage.getFormattedVariableBindings();
        assertEquals(2, formattedVariableBindings.size());
        assertEquals("foo", formattedVariableBindings.get("iso.foo"));
        assertEquals("bar", formattedVariableBindings.get("iso.bar"));
    }

    @Test
    void trapShouldProperlyCreateV2cTrapMessage() throws IOException {
        final PDU pdu = new PDU(PDU.TRAP, List.of(
                new VariableBinding(new OID("1.1"), new OctetString("foo")),
                new VariableBinding(new OID("1.2"), new OctetString("bar"))
        ));
        pdu.setRequestID(new Integer32(123));

        when(mibManager.map(any(OID.class)))
                .thenReturn("iso.foo", "iso.bar");

        final SnmpTrapMessage snmpTrapMessage = executeTrapAndGetProducedSnmpTrapMessage(SnmpConstants.version2c, pdu, TRAP_SECURITY_NAME, SecurityLevel.NOAUTH_NOPRIV);
        assertEquals(SnmpConstants.version2c, snmpTrapMessage.getVersion());
        assertEquals(TRAP_SECURITY_NAME, snmpTrapMessage.getSecurityNameString());
        assertEquals(TRAP_PEER_ADDRESS.getInetAddress().getHostAddress(), snmpTrapMessage.getPeerIpAddress());

        final Map<String, Object> trapEvent = snmpTrapMessage.getTrapEvent();
        assertEquals("2c", trapEvent.remove("version"));
        assertEquals(PDU.getTypeString(pdu.getType()), trapEvent.remove("type"));
        assertEquals(pdu.getRequestID().getValue(), trapEvent.remove("request_id"));
        assertEquals(pdu.getErrorStatus(), trapEvent.remove("error_status"));
        assertEquals(pdu.getErrorStatusText(), trapEvent.remove("error_status_text"));
        assertEquals(pdu.getErrorIndex(), trapEvent.remove("error_index"));
        assertEquals(TRAP_SECURITY_NAME, trapEvent.remove("community"));

        @SuppressWarnings("unchecked") final Map<String, Object> variableBindings = (Map<String, Object>) trapEvent.remove("variable_bindings");
        pdu.getVariableBindings().forEach(binding -> assertEquals(
                binding.getVariable().toString(),
                variableBindings.remove(binding.getOid().toString()))
        );

        // No extra trap event properties
        assertTrue(trapEvent.isEmpty());

        // No extra variable bindings
        assertTrue(variableBindings.isEmpty());

        final Map<String, Object> formattedVariableBindings = snmpTrapMessage.getFormattedVariableBindings();
        assertEquals(2, formattedVariableBindings.size());
        assertEquals("foo", formattedVariableBindings.get("iso.foo"));
        assertEquals("bar", formattedVariableBindings.get("iso.bar"));
    }

    @Test
    void trapShouldProperlyCreateV3TrapMessage() throws IOException {
        final ScopedPDU scopedPDU = new ScopedPDU();
        scopedPDU.setVariableBindings(List.of(
                new VariableBinding(new OID("1.1"), new OctetString("foo")),
                new VariableBinding(new OID("1.2"), new OctetString("bar"))
        ));
        scopedPDU.setType(ScopedPDU.TRAP);
        scopedPDU.setRequestID(new Integer32(123));

        when(mibManager.map(any(OID.class)))
                .thenReturn("iso.foo", "iso.bar");

        final String securityName = USER.getSecurityName().toString();
        final SnmpTrapMessage snmpTrapMessage = executeTrapAndGetProducedSnmpTrapMessage(SnmpConstants.version3, scopedPDU, securityName, SecurityLevel.AUTH_NOPRIV);
        assertEquals(SnmpConstants.version3, snmpTrapMessage.getVersion());
        assertEquals(securityName, snmpTrapMessage.getSecurityNameString());
        assertEquals(TRAP_PEER_ADDRESS.getInetAddress().getHostAddress(), snmpTrapMessage.getPeerIpAddress());

        final Map<String, Object> trapEvent = snmpTrapMessage.getTrapEvent();
        assertEquals("3", trapEvent.remove("version"));
        assertEquals(PDU.getTypeString(scopedPDU.getType()), trapEvent.remove("type"));
        assertEquals(scopedPDU.getRequestID().getValue(), trapEvent.remove("request_id"));
        assertEquals(scopedPDU.getErrorStatus(), trapEvent.remove("error_status"));
        assertEquals(scopedPDU.getErrorStatusText(), trapEvent.remove("error_status_text"));
        assertEquals(scopedPDU.getErrorIndex(), trapEvent.remove("error_index"));
        assertEquals(scopedPDU.getContextEngineID(), trapEvent.remove("context_engine_id"));
        assertEquals(scopedPDU.getContextName(), trapEvent.remove("context_name"));

        @SuppressWarnings("unchecked") final Map<String, Object> variableBindings = (Map<String, Object>) trapEvent.remove("variable_bindings");
        scopedPDU.getVariableBindings().forEach(binding -> assertEquals(
                binding.getVariable().toString(),
                variableBindings.remove(binding.getOid().toString()))
        );

        // No extra trap event properties
        assertTrue(trapEvent.isEmpty());

        // No extra variable bindings
        assertTrue(variableBindings.isEmpty());

        final Map<String, Object> formattedVariableBindings = snmpTrapMessage.getFormattedVariableBindings();
        assertEquals(2, formattedVariableBindings.size());
        assertEquals("foo", formattedVariableBindings.get("iso.foo"));
        assertEquals("bar", formattedVariableBindings.get("iso.bar"));
    }

    private SnmpTrapMessage executeTrapAndGetProducedSnmpTrapMessage(
            int version,
            PDU pdu,
            String securityName,
            int securityLevel
    ) throws IOException {
        try (final SnmpClient client = spy(createClient())) {
            final Snmp snmp = spy(client.getSnmp());

            when(client.getSnmp()).thenReturn(snmp);
            doNothing().when(snmp).listen();

            final SnmpTrapMessage[] message = new SnmpTrapMessage[1];
            client.doTrap(new String[0], p -> message[0] = p, new CountDownLatch(0));

            final CommandResponderEvent<Address> responderEvent = mock();
            when(responderEvent.getMessageProcessingModel())
                    .thenReturn(version);

            when(responderEvent.getPeerAddress())
                    .thenReturn(TRAP_PEER_ADDRESS);

            when(responderEvent.getSecurityName())
                    .thenReturn(securityName.getBytes());

            when(responderEvent.getPDU())
                    .thenReturn(pdu);

            when(responderEvent.getSecurityLevel())
                    .thenReturn(securityLevel);

            // Simulates an incoming trap message
            snmp.processPdu(responderEvent);

            final SnmpTrapMessage snmpTrapMessage = message[0];
            assertNotNull(snmpTrapMessage);

            pdu.getVariableBindings().forEach(
                    binding -> verify(client, times(2)).coerceVariable(binding.getVariable()));

            return snmpTrapMessage;
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"1", "2c"})
    void createTargetV1AndV2ShouldRequireCommunity(String version) throws IOException {
        try (SnmpClient client = createClient()) {
            final NullPointerException npe = assertThrows(
                    NullPointerException.class,
                    () -> client.createTarget(HOST_ADDRESS, version, 1, 1, null, null, null)
            );
            assertEquals("community is required", npe.getMessage());
        }
    }

    @Test
    void createTargetWithUnknownHostShouldThrow() throws IOException {
        try (SnmpClient client = createClient()) {
            final IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> client.createTarget("udp:unknown/161", "1", 1, 1, "public", null, null)
            );

            assertEquals("Invalid or unknown host address: `udp:unknown/161`", exception.getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"1", "2c"})
    void createTargetV1andV2ShouldCreateCommunityTarget(String version) throws IOException {
        try (SnmpClient client = createClient()) {
            final Target<Address> target = client.createTarget(HOST_ADDRESS, version, 10, 2000, "home", null, null);

            assertInstanceOf(CommunityTarget.class, target);
            final CommunityTarget<Address> communityTarget = (CommunityTarget<Address>) target;
            assertEquals(GenericAddress.parse(HOST_ADDRESS), communityTarget.getAddress());
            assertEquals(SnmpUtils.parseSnmpVersion(version), communityTarget.getVersion());
            assertEquals(2000, communityTarget.getTimeout());
            assertEquals(10, communityTarget.getRetries());
            assertEquals("home", communityTarget.getCommunity().toString());
            assertEquals(SecurityLevel.NOAUTH_NOPRIV, communityTarget.getSecurityLevel());
        }
    }

    @Test
    void createTargetV3WithoutSecurityNameShouldThrow() throws IOException {
        try (SnmpClient client = createClient()) {
            final NullPointerException npe = assertThrows(
                    NullPointerException.class,
                    () -> client.createTarget(HOST_ADDRESS, "3", 1, 1, null, null, "noauthnopriv")
            );
            assertEquals("security_name is required", npe.getMessage());
        }
    }

    @Test
    void createTargetV3WithoutSecurityLevelShouldThrow() throws IOException {
        try (SnmpClient client = createClient()) {
            final NullPointerException npe = assertThrows(
                    NullPointerException.class,
                    () -> client.createTarget(HOST_ADDRESS, "3", 1, 1, null, "guest", null)
            );
            assertEquals("security_level is required", npe.getMessage());
        }
    }

    @Test
    void createTargetV3ShouldCreateUserTarget() throws IOException {
        try (SnmpClient client = createClient()) {
            final Target<Address> target = client.createTarget(HOST_ADDRESS, "3", 5, 1000, null, "myUser", "authpriv");

            assertInstanceOf(UserTarget.class, target);
            final UserTarget<Address> userTarget = (UserTarget<Address>) target;
            assertEquals(GenericAddress.parse(HOST_ADDRESS), userTarget.getAddress());
            assertEquals(SnmpConstants.version3, userTarget.getVersion());
            assertEquals(1000, userTarget.getTimeout());
            assertEquals(5, userTarget.getRetries());
            assertEquals("myUser", userTarget.getSecurityName().toString());
            assertEquals(SecurityLevel.AUTH_PRIV, userTarget.getSecurityLevel());
        }
    }

    private Target<Address> createTarget(SnmpClient client, String address, String version) {
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
        return createClientBuilder(protocols)
                .setCloseTimeoutDuration(CLIENT_CLOSE_TIMEOUT)
                .build();
    }

    private SnmpClientBuilder createClientBuilder(Set<String> protocols) {
        return creatEmptyClientBuilder(mibManager, protocols, PORT)
                .setMessageDispatcherPoolName("FooBarWorker")
                .setMessageDispatcherPoolSize(1)
                .setLocalEngineId(LOCAL_ENGINE_ID)
                .addUsmUser(
                        USER.getSecurityName().toString(),
                        "md5",
                        USER.getAuthenticationPassphrase().toString(),
                        "des",
                        USER.getPrivacyPassphrase().toString(),
                        "authNoPriv");
    }

    private SnmpClientBuilder creatEmptyClientBuilder(MibManager mib, Set<String> protocols, int port) {
        return SnmpClient.builder(mib, protocols, port)
                .setCloseTimeoutDuration(CLIENT_CLOSE_TIMEOUT);
    }
}