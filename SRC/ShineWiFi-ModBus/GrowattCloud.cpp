/**
 * GrowattCloud.cpp - Growatt Cloud Protocol Sender
 *
 * Implements the Growatt proprietary TCP protocol to server.growatt.com:5279.
 * Designed to be added to OpenInverterGateway or similar ESP firmware
 * for dual-mode operation (local MQTT + Growatt cloud).
 *
 * Protocol: Plain TCP with XOR obfuscation (key: "Growatt", 7 bytes cycled).
 * Header (8 bytes) is cleartext, payload is XOR'd.
 * CRC-16 (Modbus polynomial 0xA001) computed over header + obfuscated payload.
 *
 * Message flow (matches stock firmware):
 *   1. TCP connect -> server.growatt.com:5279
 *   2. PING (0x16) -> wait for IDENTIFY (0x19) queries from server
 *   3. Respond to all IDENTIFY queries
 *   4. ANNOUNCE (0x03) with holding register data -> wait for ACK
 *   5. DATA (0x04) every 5 min with input register values
 *   6. PING keepalive every 30 seconds
 *   7. Handle CONFIG (0x18), REBOOT (0x20), 0x5D from server
 */

#include "GrowattCloud.h"
#include <TLog.h>
#include <time.h>

#ifdef ESP8266
#include <ESP8266WiFi.h>
#elif defined(ESP32)
#include <WiFi.h>
#endif

// ============================================================================
// Constructor
// ============================================================================

GrowattCloud::GrowattCloud()
    : _state(GCS_DISCONNECTED)
    , _transactionId(1)
    , _lastPing(0)
    , _lastDataSend(0)
    , _lastAnnounce(0)
    , _lastConnectAttempt(0)
    , _pingWaitStart(0)
    , _unackedCount(0)
    , _announceAcked(false)
    , _packetsSent(0)
    , _packetsRecv(0)
    , _reconnects(0)
    , _lastRecvTime(0)
    , _connectTime(0)
    , _silentSessions(0)
{
}

// ============================================================================
// Public API
// ============================================================================

void GrowattCloud::begin(const GrowattCloudConfig& config) {
    _config = config;
    if (_config.serverPort == 0) _config.serverPort = GROWATT_PORT_DEFAULT;
    if (_config.logIntervalMin == 0) _config.logIntervalMin = 5;
    if (_config.protocolId == 0) _config.protocolId = GROWATT_PROTO_ENC_V2;
    if (strlen(_config.serverHost) == 0) {
        strncpy(_config.serverHost, GROWATT_SERVER_DEFAULT, sizeof(_config.serverHost) - 1);
    }
    if (strlen(_config.fwVersion) == 0) {
        strncpy(_config.fwVersion, "1.7.7.7", sizeof(_config.fwVersion) - 1);
    }
    _state = GCS_DISCONNECTED;
    Log.printf("[GrowattCloud] Initialized: server=%s:%d serial=%s invSerial=%s proto=0x%04X\n",
               _config.serverHost, _config.serverPort,
               _config.dataloggerSerial, _config.inverterSerial, _config.protocolId);
}

const char* GrowattCloud::getStateName() const {
    switch (_state) {
        case GCS_DISCONNECTED: return "Disconnected";
        case GCS_CONNECTING:   return "Connecting";
        case GCS_CONNECTED:    return "Connected";
        case GCS_PING_WAIT:    return "PingWait";
        case GCS_ANNOUNCED:    return "Announced";
        case GCS_ACTIVE:       return "Active";
        case GCS_ERROR:        return "Error";
        default:               return "Unknown";
    }
}

void GrowattCloud::loop(const uint16_t* inputRegs, uint16_t numInputRegs,
                        const uint16_t* holdingRegs, uint16_t numHoldingRegs) {
    if (!_config.enabled) return;
    if (strlen(_config.dataloggerSerial) == 0) return;

    uint32_t now = millis();

    switch (_state) {
        case GCS_DISCONNECTED:
        case GCS_ERROR:
            // Don't connect until we have the inverter serial
            if (strlen(_config.inverterSerial) == 0) {
                return; // Wait for inverter serial discovery
            }
            {
                // Back off harder after sessions where the server never spoke:
                // Growatt tends to blank fresh connections made too soon.
                uint8_t shift = (_silentSessions > 4) ? 4 : _silentSessions;
                uint32_t delay = GROWATT_RECONNECT_DELAY << shift;
                if (now - _lastConnectAttempt >= delay) {
                    _connect();
                }
            }
            break;

        case GCS_CONNECTING:
            if (_client.connected()) {
                _state = GCS_CONNECTED;
                _announceAcked = false;
                _unackedCount = 0;
                Log.println("[GrowattCloud] TCP connected, sending initial PING");
                // Send initial PING immediately
                uint16_t plen = _buildPing(_txBuf);
                _sendPacket(_txBuf, plen, "PING(initial)");
                _lastPing = now;
                // Transition to PING_WAIT to handle IDENTIFY queries before ANNOUNCE
                _state = GCS_PING_WAIT;
                _pingWaitStart = now;
                Log.println("[GrowattCloud] -> GCS_PING_WAIT (waiting for IDENTIFY queries)");
            } else if (now - _lastConnectAttempt >= GROWATT_CONNECT_TIMEOUT) {
                _state = GCS_ERROR;
                Log.println("[GrowattCloud] Connection timeout -> GCS_ERROR");
            }
            break;

        case GCS_PING_WAIT:
            // Handle incoming messages (IDENTIFY queries come after PING)
            _handleReceived();

            // Keepalive PINGs during wait
            if (now - _lastPing >= GROWATT_PING_INTERVAL) {
                uint16_t plen = _buildPing(_txBuf);
                _sendPacket(_txBuf, plen, "PING(wait)");
                _lastPing = now;
            }

            // After waiting for IDENTIFY queries, proceed to ANNOUNCE
            if (now - _pingWaitStart >= GROWATT_IDENTIFY_WAIT) {
                Log.println("[GrowattCloud] IDENTIFY wait complete, proceeding to ANNOUNCE");
                _state = GCS_CONNECTED;
                _lastAnnounce = 0; // Trigger immediate ANNOUNCE
            }
            break;

        case GCS_CONNECTED: {
            // Server accepted TCP but has never sent a byte: dead session
            // (seen after abrupt reconnects) - cycle it with backoff.
            if (_lastRecvTime == 0 && now - _connectTime >= GROWATT_SILENT_TIMEOUT) {
                Log.println("[GrowattCloud] No server response since connect, cycling session");
                _silentSessions++;
                _disconnect();
                break;
            }
            // Send ANNOUNCE, wait for ACK
            if (now - _lastAnnounce >= GROWATT_ANNOUNCE_RETRY || _lastAnnounce == 0) {
                uint16_t alen = _buildAnnounce(_txBuf, holdingRegs, numHoldingRegs);
                if (_sendPacket(_txBuf, alen, "ANNOUNCE")) {
                    _lastAnnounce = now;
                }
            }
            // Check for server response
            _handleReceived();
            // Periodic PING
            if (now - _lastPing >= GROWATT_PING_INTERVAL) {
                uint16_t plen = _buildPing(_txBuf);
                _sendPacket(_txBuf, plen, "PING(connected)");
                _lastPing = now;
            }
            if (_announceAcked) {
                _state = GCS_ACTIVE;
                Log.println("[GrowattCloud] ANNOUNCE ACKed -> GCS_ACTIVE");
            }
            break;
        }

        case GCS_ANNOUNCED:
        case GCS_ACTIVE:
            // Check connection
            if (!_checkConnection()) {
                Log.println("[GrowattCloud] Connection lost in ACTIVE state");
                _disconnect();
                break;
            }
            // Handle incoming messages (IDENTIFY, CONFIGURE, ACKs)
            _handleReceived();
            // _handleReceived may have just stamped _lastRecvTime later than
            // our loop-entry 'now'; refresh it or the unsigned diff underflows.
            now = millis();
            // Server stopped talking mid-session (pings go unACKed): cycle.
            if (_lastRecvTime != 0 && now - _lastRecvTime >= GROWATT_RX_TIMEOUT) {
                Log.println("[GrowattCloud] No RX for 5 minutes in ACTIVE, cycling session");
                _disconnect();
                break;
            }
            if (_lastRecvTime == 0 && now - _connectTime >= GROWATT_SILENT_TIMEOUT) {
                Log.println("[GrowattCloud] No server response since connect, cycling session");
                _silentSessions++;
                _disconnect();
                break;
            }
            // Periodic PING
            if (now - _lastPing >= GROWATT_PING_INTERVAL) {
                uint16_t plen = _buildPing(_txBuf);
                _sendPacket(_txBuf, plen, "PING(active)");
                _lastPing = now;
            }
            // Periodic DATA report
            if (inputRegs && numInputRegs > 0) {
                uint32_t dataInterval = (uint32_t)_config.logIntervalMin * 60000UL;
                if (now - _lastDataSend >= dataInterval) {
                    uint16_t dlen = _buildData(_txBuf, inputRegs, numInputRegs);
                    if (_sendPacket(_txBuf, dlen, "DATA")) {
                        _lastDataSend = now;
                    }
                }
            }
            // Check for too many unacked messages
            if (_unackedCount >= GROWATT_MAX_UNACKED) {
                Log.printf("[GrowattCloud] Too many unacked (%d), reconnecting\n", _unackedCount);
                _disconnect();
            }
            break;
    }
}

void GrowattCloud::reconnect() {
    Log.println("[GrowattCloud] Manual reconnect requested");
    _disconnect();
}

void GrowattCloud::setInverterSerial(const char* serial) {
    strncpy(_config.inverterSerial, serial, GROWATT_SERIAL_LEN);
    _config.inverterSerial[GROWATT_SERIAL_LEN] = '\0';
    Log.printf("[GrowattCloud] Inverter serial set: %s\n", _config.inverterSerial);
}

// ============================================================================
// Connection Management
// ============================================================================

void GrowattCloud::_connect() {
    _lastConnectAttempt = millis();
    Log.printf("[GrowattCloud] Connecting to %s:%d (serial=%s invSN=%s)...\n",
               _config.serverHost, _config.serverPort,
               _config.dataloggerSerial, _config.inverterSerial);

    if (_client.connect(_config.serverHost, _config.serverPort)) {
        _state = GCS_CONNECTED;
        _announceAcked = false;
        _unackedCount = 0;
        _lastAnnounce = 0;
        _connectTime = millis();
        _lastRecvTime = 0;
        _reconnects++;
        Log.printf("[GrowattCloud] TCP connected (reconnect #%d)\n", _reconnects);

        // Send initial PING
        uint16_t plen = _buildPing(_txBuf);
        _sendPacket(_txBuf, plen, "PING(initial)");
        _lastPing = millis();

        // Wait for IDENTIFY queries before sending ANNOUNCE
        _state = GCS_PING_WAIT;
        _pingWaitStart = millis();
        Log.println("[GrowattCloud] -> GCS_PING_WAIT");
    } else {
        _state = GCS_ERROR;
        Log.println("[GrowattCloud] Connection failed -> GCS_ERROR");
    }
}

void GrowattCloud::_disconnect() {
    Log.printf("[GrowattCloud] Disconnecting (was %s)\n", getStateName());
    _client.stop();
    _state = GCS_DISCONNECTED;
    _announceAcked = false;
    _lastAnnounce = 0;
}

bool GrowattCloud::_checkConnection() {
    return _client.connected();
}

// ============================================================================
// Protocol Message Builders
// ============================================================================

/**
 * PING (0x16): Keepalive heartbeat
 * Payload: [30B datalogger_serial][0x00][0x00]
 * Server echoes the exact packet back.
 */
uint16_t GrowattCloud::_buildPing(uint8_t* buf) {
    uint16_t dataLen = GROWATT_SERIAL_LEN + 2; // serial + 2 zero bytes
    uint16_t totalLen = GROWATT_HEADER_LEN + dataLen + 2; // + CRC

    _writeHeader(buf, _transactionId++, _config.protocolId,
                 dataLen + 2, 0x01, GROWATT_FUNC_PING);

    // Payload: serial + 0x0000
    _writeSerial(buf + GROWATT_HEADER_LEN, _config.dataloggerSerial);
    buf[GROWATT_HEADER_LEN + GROWATT_SERIAL_LEN] = 0x00;
    buf[GROWATT_HEADER_LEN + GROWATT_SERIAL_LEN + 1] = 0x00;

    // XOR-encrypt payload (not header)
    if (_config.protocolId == GROWATT_PROTO_ENC_V1 ||
        _config.protocolId == GROWATT_PROTO_ENC_V2) {
        _xorEncrypt(buf, GROWATT_HEADER_LEN, dataLen);
    }

    // CRC over header + encrypted payload
    uint16_t crc = _calcCRC16(buf, GROWATT_HEADER_LEN + dataLen);
    buf[GROWATT_HEADER_LEN + dataLen] = (crc >> 8) & 0xFF;
    buf[GROWATT_HEADER_LEN + dataLen + 1] = crc & 0xFF;

    return totalLen;
}

/**
 * ANNOUNCE (0x03): Device announcement with inverter info
 * Stock firmware sends 255-byte payload with holding register values.
 * These registers contain device identity: firmware version, model name,
 * inverter serial, voltage/frequency limits, protocol version, etc.
 *
 * Register data is indexed by MODBUS ADDRESS (not array index).
 */
uint16_t GrowattCloud::_buildAnnounce(uint8_t* buf,
                                       const uint16_t* holdingRegs,
                                       uint16_t numHoldingRegs) {
    const uint16_t payloadLen = 255;
    const uint16_t payloadOffset = GROWATT_HEADER_LEN;
    uint8_t* p = buf + payloadOffset;

    // Zero the entire payload area first
    memset(p, 0, payloadLen);

    // Bytes 0-29: Datalogger serial
    _writeSerial(p + 0, _config.dataloggerSerial);

    // Bytes 30-59: Inverter serial
    _writeSerial(p + 30, _config.inverterSerial);

    // Bytes 60-65: Timestamp
    _writeTimestamp(p + 60);

    // Byte 66: Inverter type
    p[66] = 0x02;

    // Bytes 67-70: Block 1 descriptor (start=0, end=44)
    p[67] = 0x00; p[68] = 0x00; // start register 0
    p[69] = 0x00; p[70] = 44;   // end register 44

    // Bytes 71-160: Holding registers 0-44 (45 regs x 2 bytes = 90 bytes)
    // Index by MODBUS ADDRESS, not array index
    if (holdingRegs && numHoldingRegs > 0) {
        for (uint16_t addr = 0; addr < 45 && addr < numHoldingRegs; addr++) {
            p[71 + addr * 2]     = (holdingRegs[addr] >> 8) & 0xFF;
            p[71 + addr * 2 + 1] = holdingRegs[addr] & 0xFF;
        }
    }

    // Block 2 descriptor at payload 161-164
    p[161] = 0x00; p[162] = 45;   // Block 2 start register = 45
    p[163] = 0x00; p[164] = 89;   // Block 2 end register = 89

    // Bytes 165-250: Holding registers 47-89 (43 regs x 2 bytes = 86 bytes)
    if (holdingRegs && numHoldingRegs > 47) {
        for (uint16_t addr = 47; addr < 90 && addr < numHoldingRegs; addr++) {
            uint16_t offset = 165 + (addr - 47) * 2;
            p[offset]     = (holdingRegs[addr] >> 8) & 0xFF;
            p[offset + 1] = holdingRegs[addr] & 0xFF;
        }
    }

    // Bytes 251-254: Zero padding (already zeroed by memset)

    // Log first few non-zero register values for debugging
    {
        int nonZero = 0;
        for (uint16_t i = 0; i < 45 && holdingRegs && i < numHoldingRegs; i++) {
            if (holdingRegs[i] != 0) nonZero++;
        }
        Log.printf("[GrowattCloud] ANNOUNCE: %d non-zero holding regs in Block1, invSN=%s\n",
                   nonZero, _config.inverterSerial);
    }

    // Header: data_len = 257 (payload 255 + unit_id 1 + func_code 1)
    _writeHeader(buf, _transactionId++, _config.protocolId,
                 payloadLen + 2, 0x01, GROWATT_FUNC_ANNOUNCE);

    // XOR-encrypt payload (not header)
    if (_config.protocolId == GROWATT_PROTO_ENC_V1 ||
        _config.protocolId == GROWATT_PROTO_ENC_V2) {
        _xorEncrypt(buf, payloadOffset, payloadLen);
    }

    // CRC over header + XOR'd payload
    uint16_t crc = _calcCRC16(buf, payloadOffset + payloadLen);
    buf[payloadOffset + payloadLen]     = (crc >> 8) & 0xFF;
    buf[payloadOffset + payloadLen + 1] = crc & 0xFF;

    Log.printf("[GrowattCloud] ANNOUNCE built: %d bytes, CRC=0x%04X\n",
               payloadOffset + payloadLen + 2, crc);

    return payloadOffset + payloadLen + 2; // 8 + 255 + 2 = 265
}

/**
 * DATA (0x04): Periodic inverter telemetry report
 * 265 bytes total (8 header + 255 payload + 2 CRC)
 * Payload layout (255 bytes, fixed size):
 *   [0-29]    Datalogger serial (30B NUL-padded)
 *   [30-59]   Inverter serial (30B NUL-padded)
 *   [60-65]   Timestamp (6x uint8: Y-2000, M, D, H, M, S)
 *   [66]      Inverter type = 0x02
 *   [67-68]   Block 1 start register = 0 (uint16 BE)
 *   [69-70]   Block 1 end register = 44 (uint16 BE)
 *   [71-160]  FC04 input registers 0-44 (45 x 2 = 90 bytes, uint16 BE)
 *   [161-162] Block 2 start register = 45
 *   [163-164] Block 2 end register = 89
 *   [165-250] FC04 input registers 47-89 (43 x 2 = 86 bytes, uint16 BE)
 *   [251-254] Zero padding
 *
 * CRITICAL: inputRegs[] MUST be indexed by MODBUS ADDRESS (not array index).
 */
uint16_t GrowattCloud::_buildData(uint8_t* buf,
                                   const uint16_t* inputRegs,
                                   uint16_t numInputRegs) {
    const uint16_t payloadLen = 255;
    const uint16_t payloadOffset = GROWATT_HEADER_LEN;
    uint8_t* p = buf + payloadOffset;

    // Zero the entire payload area first
    memset(p, 0, payloadLen);

    // Bytes 0-29: Datalogger serial
    _writeSerial(p + 0, _config.dataloggerSerial);

    // Bytes 30-59: Inverter serial
    _writeSerial(p + 30, _config.inverterSerial);

    // Bytes 60-65: Timestamp
    _writeTimestamp(p + 60);

    // Byte 66: Inverter type
    p[66] = 0x02;

    // Bytes 67-70: Block 1 descriptor (start=0, end=44)
    p[67] = 0x00; p[68] = 0x00; // start register 0
    p[69] = 0x00; p[70] = 44;   // end register 44

    // Bytes 71-160: Input registers 0-44 indexed by MODBUS ADDRESS
    for (uint16_t addr = 0; addr < 45 && addr < numInputRegs; addr++) {
        p[71 + addr * 2]     = (inputRegs[addr] >> 8) & 0xFF;
        p[71 + addr * 2 + 1] = inputRegs[addr] & 0xFF;
    }

    // Block 2 descriptor at payload 161-164
    p[161] = 0x00; p[162] = 45;   // Block 2 start register = 45
    p[163] = 0x00; p[164] = 89;   // Block 2 end register = 89

    // Bytes 165-250: Input registers 47-89 indexed by MODBUS ADDRESS
    for (uint16_t addr = 47; addr < 90 && addr < numInputRegs; addr++) {
        uint16_t offset = 165 + (addr - 47) * 2;
        p[offset]     = (inputRegs[addr] >> 8) & 0xFF;
        p[offset + 1] = inputRegs[addr] & 0xFF;
    }

    // Bytes 251-254: Zero padding (already zeroed by memset)

    // Log key register values for debugging
    {
        uint16_t status = (numInputRegs > 0) ? inputRegs[0] : 0;
        // Legacy record slots: Ppv at 1-2, total Pac at 11-12 (both 32-bit)
        uint32_t dcPower = 0, acPower = 0;
        if (numInputRegs > 2) dcPower = ((uint32_t)inputRegs[1] << 16) | inputRegs[2];
        if (numInputRegs > 12) acPower = ((uint32_t)inputRegs[11] << 16) | inputRegs[12];
        Log.printf("[GrowattCloud] DATA: status=%d dcPower=%u(%.1fW) acPower=%u(%.1fW) ts=%02d-%02d-%02d %02d:%02d:%02d numRegs=%d\n",
                   status, dcPower, dcPower / 10.0, acPower, acPower / 10.0,
                   p[60], p[61], p[62], p[63], p[64], p[65], numInputRegs);
    }

    // Header: data_len = 257 (payload 255 + unit_id 1 + func_code 1)
    _writeHeader(buf, _transactionId++, _config.protocolId,
                 payloadLen + 2, 0x01, GROWATT_FUNC_DATA);

    // XOR-encrypt payload (not header)
    if (_config.protocolId == GROWATT_PROTO_ENC_V1 ||
        _config.protocolId == GROWATT_PROTO_ENC_V2) {
        _xorEncrypt(buf, payloadOffset, payloadLen);
    }

    // CRC over header + XOR'd payload
    uint16_t crc = _calcCRC16(buf, payloadOffset + payloadLen);
    buf[payloadOffset + payloadLen]     = (crc >> 8) & 0xFF;
    buf[payloadOffset + payloadLen + 1] = crc & 0xFF;

    Log.printf("[GrowattCloud] DATA built: %d bytes, CRC=0x%04X\n",
               payloadOffset + payloadLen + 2, crc);

    return payloadOffset + payloadLen + 2; // 8 + 255 + 2 = 265
}

/**
 * Build a generic ACK response for server commands.
 * Format: [header][serial(30)][0x00][0x01]
 */
uint16_t GrowattCloud::_buildGenericAck(uint8_t* buf, uint8_t funcCode) {
    uint16_t pos = GROWATT_HEADER_LEN;

    _writeSerial(buf + pos, _config.dataloggerSerial);
    pos += GROWATT_SERIAL_LEN;
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;

    uint16_t dataLen = pos - GROWATT_HEADER_LEN;
    _writeHeader(buf, _transactionId++, _config.protocolId,
                 dataLen + 2, 0x01, funcCode);

    if (_config.protocolId == GROWATT_PROTO_ENC_V1 ||
        _config.protocolId == GROWATT_PROTO_ENC_V2) {
        _xorEncrypt(buf, GROWATT_HEADER_LEN, dataLen);
    }

    uint16_t crc = _calcCRC16(buf, GROWATT_HEADER_LEN + dataLen);
    buf[pos++] = (crc >> 8) & 0xFF;
    buf[pos++] = crc & 0xFF;

    return pos;
}

// ============================================================================
// Receive Handler
// ============================================================================

/**
 * Process ALL available messages from the server.
 * Server may batch multiple messages in one TCP segment.
 */
void GrowattCloud::_handleReceived() {
    // Process all available messages in a loop
    int messagesProcessed = 0;
    while (_client.available() && messagesProcessed < 20) {
        int len = _readPacket(_rxBuf, GROWATT_MAX_PACKET);
        if (len < GROWATT_HEADER_LEN) break;

        _packetsRecv++;
        messagesProcessed++;
        // Any valid packet from the server proves the link is alive: clear the
        // unacked backlog (we also send packets the server never ACKs, e.g.
        // IDENTIFY responses) and reset the silent-session escalation.
        _unackedCount = 0;
        _lastRecvTime = millis();
        _silentSessions = 0;

        uint16_t transId = (_rxBuf[0] << 8) | _rxBuf[1];
        uint16_t protoId = (_rxBuf[2] << 8) | _rxBuf[3];
        uint16_t dataLen = (_rxBuf[4] << 8) | _rxBuf[5];
        // unitId at _rxBuf[6] is always 0x01
        uint8_t  funcCode = _rxBuf[7];

        // Decrypt payload only (not header, not CRC)
        // Payload is at buf[8..8+dataLen-2-1], CRC is last 2 bytes
        uint16_t payloadBodyLen = (dataLen > 2) ? (dataLen - 2) : 0;
        if (protoId == GROWATT_PROTO_ENC_V1 || protoId == GROWATT_PROTO_ENC_V2) {
            // Only decrypt the payload body, NOT the trailing CRC
            _xorDecrypt(_rxBuf, GROWATT_HEADER_LEN, payloadBodyLen);
        }

        // Function code name for logging
        const char* fname = "UNKNOWN";
        switch (funcCode) {
            case GROWATT_FUNC_ANNOUNCE:  fname = "ANNOUNCE_ACK"; break;
            case GROWATT_FUNC_DATA:      fname = "DATA_ACK"; break;
            case GROWATT_FUNC_PING:      fname = "PING_ACK"; break;
            case GROWATT_FUNC_CONFIGURE: fname = "CONFIG"; break;
            case GROWATT_FUNC_IDENTIFY:  fname = "IDENTIFY"; break;
            case GROWATT_FUNC_REBOOT:    fname = "REBOOT"; break;
            case GROWATT_FUNC_BUFFERED:  fname = "BUFFERED_ACK"; break;
            case GROWATT_FUNC_5D:        fname = "FUNC_5D"; break;
        }

        Log.printf("[GrowattCloud] RX %s(0x%02X) trans=%d proto=0x%04X len=%d\n",
                   fname, funcCode, transId, protoId, dataLen);

        switch (funcCode) {
            case GROWATT_FUNC_PING:
                // PING echo from server - connection is alive
                Log.println("[GrowattCloud]   PING ACK OK");
                break;

            case GROWATT_FUNC_ANNOUNCE:
                // ACK for our ANNOUNCE
                _handleAck(GROWATT_FUNC_ANNOUNCE);
                break;

            case GROWATT_FUNC_DATA:
                // ACK for our DATA
                _handleAck(GROWATT_FUNC_DATA);
                break;

            case GROWATT_FUNC_BUFFERED:
                // ACK for buffered DATA
                Log.println("[GrowattCloud]   BUFFERED DATA ACK");
                if (_unackedCount > 0) _unackedCount--;
                break;

            case GROWATT_FUNC_IDENTIFY:
                // Server is querying our configuration
                _handleIdentify(_rxBuf, len);
                break;

            case GROWATT_FUNC_CONFIGURE:
                // Server is pushing configuration changes
                _handleConfigure(_rxBuf, len);
                break;

            case GROWATT_FUNC_REBOOT: {
                // Server reboot command -- ACK but do NOT reboot
                Log.println("[GrowattCloud]   REBOOT command -> ACKing (NOT rebooting)");
                uint16_t ackLen = _buildGenericAck(_txBuf, GROWATT_FUNC_REBOOT);
                _sendPacket(_txBuf, ackLen, "REBOOT_ACK");
                break;
            }

            case GROWATT_FUNC_5D: {
                // Unknown function 0x5D (possibly firmware update data)
                Log.printf("[GrowattCloud]   FUNC_5D: %d bytes payload -> ACKing\n", payloadBodyLen);
                uint16_t ackLen = _buildGenericAck(_txBuf, GROWATT_FUNC_5D);
                _sendPacket(_txBuf, ackLen, "5D_ACK");
                break;
            }

            default: {
                // Unknown function -- send generic ACK to prevent server retries
                Log.printf("[GrowattCloud]   Unknown func 0x%02X -> sending generic ACK\n", funcCode);
                uint16_t ackLen = _buildGenericAck(_txBuf, funcCode);
                _sendPacket(_txBuf, ackLen, "GENERIC_ACK");
                break;
            }
        }
    }

    if (messagesProcessed > 1) {
        Log.printf("[GrowattCloud] Processed %d messages in batch\n", messagesProcessed);
    }
}

void GrowattCloud::_handleAck(uint8_t funcCode) {
    if (_unackedCount > 0) _unackedCount--;

    if (funcCode == GROWATT_FUNC_ANNOUNCE) {
        _announceAcked = true;
        Log.println("[GrowattCloud]   *** ANNOUNCE ACK received ***");
    } else if (funcCode == GROWATT_FUNC_DATA) {
        Log.println("[GrowattCloud]   *** DATA ACK received ***");
    }
}

/**
 * Handle IDENTIFY (0x19) queries from server.
 * Server asks for specific config items; we must respond honestly.
 *
 * CRITICAL: For config items 0x11/0x13 (server address), ALWAYS respond
 * with "server.growatt.com" even if we're running locally. Otherwise
 * the server force-reconfigures and reboots us.
 */
void GrowattCloud::_handleIdentify(const uint8_t* data, uint16_t len) {
    // Payload starts at offset 8 (after header)
    // Payload: [serial(30B)][configItem(2B)][...]
    if (len < GROWATT_HEADER_LEN + GROWATT_SERIAL_LEN + 2) {
        Log.printf("[GrowattCloud]   IDENTIFY: payload too short (%d bytes)\n", len);
        return;
    }

    uint16_t payloadStart = GROWATT_HEADER_LEN;
    // Config item is at payload offset 30 (after 30-byte serial)
    uint16_t configItem = (data[payloadStart + 30] << 8) | data[payloadStart + 31];

    Log.printf("[GrowattCloud]   IDENTIFY query: config item 0x%04X\n", configItem);

    // Build response
    uint16_t pos = GROWATT_HEADER_LEN;

    // Echo datalogger serial (30 bytes padded)
    _writeSerial(_txBuf + pos, _config.dataloggerSerial);
    pos += GROWATT_SERIAL_LEN;

    // Config item
    _txBuf[pos++] = (configItem >> 8) & 0xFF;
    _txBuf[pos++] = configItem & 0xFF;

    // Value depends on config item
    switch (configItem) {
        case GROWATT_CFG_INTERVAL: {
            // Protocol version (Python responds with 5)
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x01; // length = 1
            _txBuf[pos++] = 5; // protocol version
            Log.println("[GrowattCloud]   -> Responding: protocol version = 5");
            break;
        }
        case GROWATT_CFG_ADDR_MIN: {
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x01;
            _txBuf[pos++] = 1; // Modbus addr min
            Log.println("[GrowattCloud]   -> Responding: addr_min = 1");
            break;
        }
        case GROWATT_CFG_ADDR_MAX: {
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x01;
            _txBuf[pos++] = 1; // Modbus addr max (single inverter)
            Log.println("[GrowattCloud]   -> Responding: addr_max = 1");
            break;
        }
        case GROWATT_CFG_SERVER_PORT_U16: {
            // Server port as uint16
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x02; // length = 2
            _txBuf[pos++] = (GROWATT_PORT_DEFAULT >> 8) & 0xFF;
            _txBuf[pos++] = GROWATT_PORT_DEFAULT & 0xFF;
            Log.printf("[GrowattCloud]   -> Responding: server_port_u16 = %d\n", GROWATT_PORT_DEFAULT);
            break;
        }
        case GROWATT_CFG_DATALOGGER_ID: {
            uint8_t slen = strlen(_config.dataloggerSerial);
            if (slen > 10) slen = 10; // Match stock: always 10 bytes
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, _config.dataloggerSerial, slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: datalogger_id = %s (%dB)\n",
                       _config.dataloggerSerial, slen);
            break;
        }
        case GROWATT_CFG_INVERTER_ID: {
            // Inverter serial -- stock responds with 10 bytes
            uint8_t slen = strlen(_config.inverterSerial);
            if (slen > 10) slen = 10;
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, _config.inverterSerial, slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: inverter_id = %s (%dB)\n",
                       _config.inverterSerial, slen);
            break;
        }
        case GROWATT_CFG_LOCAL_IP: {
            String ip = WiFi.localIP().toString();
            uint8_t slen = ip.length();
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, ip.c_str(), slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: local_ip = %s\n", ip.c_str());
            break;
        }
        case GROWATT_CFG_NETMASK: {
            // 0x0F = netmask (NOT local port as previously defined)
            String nm = WiFi.subnetMask().toString();
            uint8_t slen = nm.length();
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, nm.c_str(), slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: netmask = %s\n", nm.c_str());
            break;
        }
        case GROWATT_CFG_MAC: {
            String mac = WiFi.macAddress(); // "AA:BB:CC:DD:EE:FF"
            uint8_t slen = mac.length();
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, mac.c_str(), slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: mac = %s\n", mac.c_str());
            break;
        }
        case GROWATT_CFG_SERVER_ADDR: {
            // Server address
            const char* official = GROWATT_SERVER_DEFAULT;
            uint8_t slen = strlen(official);
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, official, slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: server_addr = %s\n", official);
            break;
        }
        case GROWATT_CFG_SERVER_PORT: {
            // Server port as string
            char portStr[8];
            snprintf(portStr, sizeof(portStr), "%d", GROWATT_PORT_DEFAULT);
            uint8_t slen = strlen(portStr);
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, portStr, slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: server_port_str = %s\n", portStr);
            break;
        }
        case GROWATT_CFG_SERVER_ADDR2: {
            // CRITICAL: Always respond with the official server address!
            const char* official = GROWATT_SERVER_DEFAULT;
            uint8_t slen = strlen(official);
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, official, slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: server_addr2 = %s\n", official);
            break;
        }
        case GROWATT_CFG_FW_VERSION: {
            uint8_t slen = strlen(_config.fwVersion);
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, _config.fwVersion, slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: fw_version = %s\n", _config.fwVersion);
            break;
        }
        case GROWATT_CFG_TIME: {
            // Current time as 6-byte timestamp
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x06; // length = 6
            _writeTimestamp(_txBuf + pos);
            Log.printf("[GrowattCloud]   -> Responding: time = %02X%02X%02X%02X%02X%02X\n",
                       _txBuf[pos], _txBuf[pos+1], _txBuf[pos+2],
                       _txBuf[pos+3], _txBuf[pos+4], _txBuf[pos+5]);
            pos += 6;
            break;
        }
        case GROWATT_CFG_WIFI_SSID: {
            // WiFi SSID
            String ssid = WiFi.SSID();
            uint8_t slen = ssid.length();
            if (slen > 30) slen = 30;
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, ssid.c_str(), slen);
            pos += slen;
            Log.printf("[GrowattCloud]   -> Responding: wifi_ssid = %s (%dB)\n", ssid.c_str(), slen);
            break;
        }
        default: {
            // Unknown config item - respond with empty
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x00;
            Log.printf("[GrowattCloud]   -> Unknown config item 0x%04X, responding empty\n", configItem);
            break;
        }
    }

    uint16_t dataLen = pos - GROWATT_HEADER_LEN;
    _writeHeader(_txBuf, _transactionId++, _config.protocolId,
                 dataLen + 2, 0x01, GROWATT_FUNC_IDENTIFY);

    if (_config.protocolId == GROWATT_PROTO_ENC_V1 ||
        _config.protocolId == GROWATT_PROTO_ENC_V2) {
        _xorEncrypt(_txBuf, GROWATT_HEADER_LEN, dataLen);
    }

    uint16_t crc = _calcCRC16(_txBuf, GROWATT_HEADER_LEN + dataLen);
    _txBuf[pos++] = (crc >> 8) & 0xFF;
    _txBuf[pos++] = crc & 0xFF;

    _sendPacket(_txBuf, pos, "IDENTIFY_RESP");
}

/**
 * Handle CONFIGURE (0x18) from server.
 * Always ACK to prevent server from retrying.
 * Ignore actual config changes since we manage our own config.
 */
void GrowattCloud::_handleConfigure(const uint8_t* data, uint16_t len) {
    if (len < GROWATT_HEADER_LEN + GROWATT_SERIAL_LEN + 4) {
        Log.printf("[GrowattCloud]   CONFIG: payload too short (%d bytes)\n", len);
        return;
    }

    uint16_t payloadStart = GROWATT_HEADER_LEN;
    uint16_t configItem = (data[payloadStart + 30] << 8) | data[payloadStart + 31];

    Log.printf("[GrowattCloud]   CONFIG push: item 0x%04X (ACKing, ignoring)\n", configItem);

    // Build ACK response: [header][serial(30)][config_item(2)][0x00 0x01][0x00]
    uint16_t pos = GROWATT_HEADER_LEN;
    _writeSerial(_txBuf + pos, _config.dataloggerSerial);
    pos += GROWATT_SERIAL_LEN;
    _txBuf[pos++] = (configItem >> 8) & 0xFF;
    _txBuf[pos++] = configItem & 0xFF;
    _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x01; // length = 1
    _txBuf[pos++] = 0x00; // ACK = success

    uint16_t dataLen = pos - GROWATT_HEADER_LEN;
    _writeHeader(_txBuf, _transactionId++, _config.protocolId,
                 dataLen + 2, 0x01, GROWATT_FUNC_CONFIGURE);

    if (_config.protocolId == GROWATT_PROTO_ENC_V1 ||
        _config.protocolId == GROWATT_PROTO_ENC_V2) {
        _xorEncrypt(_txBuf, GROWATT_HEADER_LEN, dataLen);
    }

    uint16_t crc = _calcCRC16(_txBuf, GROWATT_HEADER_LEN + dataLen);
    _txBuf[pos++] = (crc >> 8) & 0xFF;
    _txBuf[pos++] = crc & 0xFF;

    _sendPacket(_txBuf, pos, "CONFIG_ACK");
}

// ============================================================================
// Header, Encryption, CRC
// ============================================================================

void GrowattCloud::_writeHeader(uint8_t* buf, uint16_t transId, uint16_t protoId,
                                 uint16_t dataLen, uint8_t unitId, uint8_t funcCode) {
    buf[0] = (transId >> 8) & 0xFF;
    buf[1] = transId & 0xFF;
    buf[2] = (protoId >> 8) & 0xFF;
    buf[3] = protoId & 0xFF;
    buf[4] = (dataLen >> 8) & 0xFF;
    buf[5] = dataLen & 0xFF;
    buf[6] = unitId;
    buf[7] = funcCode;
}

void GrowattCloud::_xorEncrypt(uint8_t* data, uint16_t offset, uint16_t len) {
    for (uint16_t i = 0; i < len; i++) {
        data[offset + i] ^= GROWATT_XOR_MASK[i % GROWATT_XOR_MASK_LEN];
    }
}

void GrowattCloud::_xorDecrypt(uint8_t* data, uint16_t offset, uint16_t len) {
    // XOR is its own inverse
    _xorEncrypt(data, offset, len);
}

/**
 * Modbus CRC-16 (polynomial 0xA001)
 */
uint16_t GrowattCloud::_calcCRC16(const uint8_t* data, uint16_t len) {
    uint16_t crc = 0xFFFF;
    for (uint16_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

void GrowattCloud::_writeSerial(uint8_t* buf, const char* serial) {
    memset(buf, 0, GROWATT_SERIAL_LEN);
    if (serial) {
        uint8_t len = strlen(serial);
        if (len > GROWATT_SERIAL_LEN) len = GROWATT_SERIAL_LEN;
        memcpy(buf, serial, len);
    }
}

void GrowattCloud::_writeTimestamp(uint8_t* buf) {
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);

    // Timestamp: 6 single bytes (NOT 2-byte shorts)
    buf[0] = (uint8_t)(timeinfo.tm_year + 1900 - 2000); // Year - 2000
    buf[1] = (uint8_t)(timeinfo.tm_mon + 1);             // Month 1-12
    buf[2] = (uint8_t)(timeinfo.tm_mday);                // Day 1-31
    buf[3] = (uint8_t)(timeinfo.tm_hour);                // Hour 0-23
    buf[4] = (uint8_t)(timeinfo.tm_min);                 // Minute 0-59
    buf[5] = (uint8_t)(timeinfo.tm_sec);                 // Second 0-59
}

// ============================================================================
// Send / Receive Helpers
// ============================================================================

bool GrowattCloud::_sendPacket(uint8_t* buf, uint16_t len, const char* label) {
    if (!_client.connected()) {
        Log.printf("[GrowattCloud] TX %s FAILED: not connected\n", label);
        return false;
    }

    size_t written = _client.write(buf, len);
    if (written == len) {
        _packetsSent++;
        _unackedCount++;
        uint16_t crc = (buf[len-2] << 8) | buf[len-1];
        Log.printf("[GrowattCloud] TX %s: %d bytes, trans=%d, func=0x%02X, CRC=0x%04X\n",
                   label, len, (buf[0] << 8) | buf[1], buf[7], crc);
        return true;
    }
    Log.printf("[GrowattCloud] TX %s FAILED: wrote %d/%d\n", label, written, len);
    return false;
}

int GrowattCloud::_readPacket(uint8_t* buf, uint16_t maxLen) {
    if (!_client.available()) return 0;

    // Read header first (8 bytes)
    int headerRead = 0;
    uint32_t start = millis();
    while (headerRead < GROWATT_HEADER_LEN && millis() - start < GROWATT_READ_TIMEOUT) {
        if (_client.available()) {
            buf[headerRead++] = _client.read();
        } else {
            delay(1);
        }
    }
    if (headerRead < GROWATT_HEADER_LEN) {
        Log.printf("[GrowattCloud] RX: incomplete header (%d/%d bytes)\n",
                   headerRead, GROWATT_HEADER_LEN);
        return headerRead;
    }

    // Extract data length from header
    uint16_t dataLen = (buf[4] << 8) | buf[5];
    if (dataLen > maxLen - GROWATT_HEADER_LEN) {
        // Packet too large, drain and discard
        Log.printf("[GrowattCloud] RX: packet too large (dataLen=%d, max=%d), draining\n",
                   dataLen, maxLen - GROWATT_HEADER_LEN);
        while (_client.available()) _client.read();
        return GROWATT_HEADER_LEN;
    }

    // Read remaining data (payload body + CRC)
    // Wire format after header: payload_body(dataLen-2) + CRC(2) = dataLen bytes
    int dataRead = 0;
    start = millis();
    while (dataRead < dataLen && millis() - start < GROWATT_READ_TIMEOUT) {
        if (_client.available()) {
            buf[GROWATT_HEADER_LEN + dataRead++] = _client.read();
        } else {
            delay(1);
        }
    }

    if (dataRead < dataLen) {
        Log.printf("[GrowattCloud] RX: incomplete body (%d/%d bytes)\n", dataRead, dataLen);
    }

    return GROWATT_HEADER_LEN + dataRead;
}

void GrowattCloud::_logHex(const char* prefix, const uint8_t* data, uint16_t len, uint16_t maxBytes) {
    char hexBuf[128];
    uint16_t show = (len < maxBytes) ? len : maxBytes;
    uint16_t pos = 0;
    for (uint16_t i = 0; i < show && pos < sizeof(hexBuf) - 4; i++) {
        pos += snprintf(hexBuf + pos, sizeof(hexBuf) - pos, "%02X", data[i]);
    }
    if (len > maxBytes) {
        snprintf(hexBuf + pos, sizeof(hexBuf) - pos, "...");
    }
    Log.printf("[GrowattCloud] %s: %s (%dB)\n", prefix, hexBuf, len);
}
