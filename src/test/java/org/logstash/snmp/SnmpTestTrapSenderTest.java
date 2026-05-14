package org.logstash.snmp;

import org.junit.jupiter.api.Test;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.smi.Address;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SnmpTestTrapSenderTest {

    @Test
    void sendInformV2cReturnsTrueWhenResponseHasNoSnmpError() throws IOException {
        final Snmp snmp = mock(Snmp.class);
        final ResponseEvent<Address> response = mock(ResponseEvent.class);
        final PDU responsePdu = new PDU();
        responsePdu.setErrorStatus(PDU.noError);

        when(snmp.send(any(PDU.class), any())).thenReturn(response);
        when(response.getResponse()).thenReturn(responsePdu);

        final SnmpTestTrapSender sender = new SnmpTestTrapSender(snmp);

        assertTrue(sender.sendInformV2c("udp:127.0.0.1/161", "public", Map.of("1.3.6.1.2.1.1.1.0", "ok")));
    }

    @Test
    void sendInformV2cReturnsFalseWhenResponsePduReportsError() throws IOException {
        final Snmp snmp = mock(Snmp.class);
        final ResponseEvent<Address> response = mock(ResponseEvent.class);
        final PDU responsePdu = new PDU();
        responsePdu.setErrorStatus(PDU.authorizationError);

        when(snmp.send(any(PDU.class), any())).thenReturn(response);
        when(response.getResponse()).thenReturn(responsePdu);

        final SnmpTestTrapSender sender = new SnmpTestTrapSender(snmp);

        assertFalse(sender.sendInformV2c("udp:127.0.0.1/161", "public", Map.of("1.3.6.1.2.1.1.1.0", "error")));
    }

    @Test
    void sendInformV2cRaisesWhenResponseEventContainsTransportError() throws IOException {
        final Snmp snmp = mock(Snmp.class);
        final ResponseEvent<Address> response = mock(ResponseEvent.class);
        final IOException transportError = new IOException("transport failure");

        when(snmp.send(any(PDU.class), any())).thenReturn(response);
        when(response.getError()).thenReturn(transportError);

        final SnmpTestTrapSender sender = new SnmpTestTrapSender(snmp);

        final RuntimeException exception = assertThrows(RuntimeException.class,
                () -> sender.sendInformV2c("udp:127.0.0.1/161", "public", Map.of("1.3.6.1.2.1.1.1.0", "error")));

        assertTrue(exception.getCause() instanceof IOException);
    }
}