package org.logstash.snmp;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.snmp4j.TransportStateReference;
import org.snmp4j.asn1.BERInputStream;
import org.snmp4j.asn1.BEROutputStream;
import org.snmp4j.mp.StatusInformation;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.SecurityParameters;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.SecurityStateReference;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmTimeEntry;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OctetString;

import java.io.IOException;
import java.util.List;

final class PersistentUsm extends USM {
    private static final Logger logger = LogManager.getLogger(PersistentUsm.class);

    private final String persistencePath;
    private final OctetString localEngineId;
    private String persistedRemoteTimeSignature;

    PersistentUsm(
            final SecurityProtocols securityProtocols,
            final OctetString localEngineId,
            final int engineBoots,
            final String persistencePath
    ) {
        super(securityProtocols, localEngineId, engineBoots);
        this.persistencePath = persistencePath;
        this.localEngineId = localEngineId;
        restoreRemoteEngineTimeEntries();
        this.persistedRemoteTimeSignature = EngineBootsStore.remoteEngineTimeSignature(getTimeTable(), localEngineId);
    }

    @Override
    public int processIncomingMsg(
            final int messageProcessingModel,
            final int maxMessageSize,
            final SecurityParameters securityParameters,
            final SecurityModel securityModel,
            final int securityLevel,
            final BERInputStream wholeMsg,
            final TransportStateReference tmStateReference,
            final OctetString securityEngineID,
            final OctetString securityName,
            final BEROutputStream scopedPDU,
            final Integer32 maxSizeResponseScopedPDU,
            final SecurityStateReference securityStateReference,
            final StatusInformation statusInformation
    ) throws IOException {
        final int status = super.processIncomingMsg(
                messageProcessingModel,
                maxMessageSize,
                securityParameters,
                securityModel,
                securityLevel,
                wholeMsg,
                tmStateReference,
                securityEngineID,
                securityName,
                scopedPDU,
                maxSizeResponseScopedPDU,
                securityStateReference,
                statusInformation
        );
            logAuthoritativeEngineReportIfNeeded(status, securityEngineID, tmStateReference, securityName, statusInformation);
        persistNow();
        return status;
    }

    @Override
    public void removeEngineTime(final OctetString engineId) {
        super.removeEngineTime(engineId);
        persistNow();
    }

    synchronized void persistNow() {
        if (persistencePath == null || persistencePath.isBlank()) {
            return;
        }

        final String currentRemoteTimeSignature = EngineBootsStore.remoteEngineTimeSignature(getTimeTable(), localEngineId);
        if (currentRemoteTimeSignature.equals(persistedRemoteTimeSignature)) {
            return;
        }

        EngineBootsStore.persistRemoteEngineTimeEntries(persistencePath, localEngineId, getTimeTable());
        persistedRemoteTimeSignature = currentRemoteTimeSignature;
    }

    private void restoreRemoteEngineTimeEntries() {
        final List<UsmTimeEntry> persistedRemoteEntries = EngineBootsStore.loadRemoteEngineTimeEntries(persistencePath, localEngineId);
        persistedRemoteEntries.forEach(entry -> getTimeTable().addEntry(entry));
    }

    void logAuthoritativeEngineReportIfNeeded(
            final int status,
            final OctetString securityEngineId,
            final TransportStateReference tmStateReference,
            final OctetString securityName,
            final StatusInformation statusInformation
    ) {
        if (status != SnmpConstants.SNMPv3_USM_NOT_IN_TIME_WINDOW || statusInformation == null) {
            return;
        }

        final UsmTimeEntry incomingEngineTimeEntry = securityEngineId == null ? null : getTimeTable().getEntry(securityEngineId);
        final Integer incomingEngineBoots = incomingEngineTimeEntry == null ? null : incomingEngineTimeEntry.getEngineBoots();
        final Integer incomingEngineTime = incomingEngineTimeEntry == null ? null : incomingEngineTimeEntry.getLatestReceivedTime();

        logger.info(
            "SNMPv3 receiver returning REPORT after {}. local_engine_id={}, engine_boots={}, engine_time={}, incoming_engine_boots={}, incoming_engine_time={}, security_name={}, error_indication={}",
            SnmpConstants.usmErrorMessage(status),
                localEngineId.toHexString(),
                getEngineBoots(),
                getEngineTime(),
                incomingEngineBoots,
                incomingEngineTime,
                securityName,
                statusInformation.getErrorIndication()
        );
    }
}