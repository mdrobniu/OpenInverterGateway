/**
 * GrowattCloud.cpp - Growatt Cloud Protocol Sender
 *
 * Implements the Growatt proprietary TCP protocol to server.growatt.com:5279.
 * Designed to be added to OpenInverterGateway or similar ESP firmware
 * for dual-mode operation (local MQTT + Growatt cloud).
 *
 * Protocol: Plain TCP with XOR obfuscation (key: "Growatt", 7 bytes cycled).
 * Header (8 bytes) is cleartext, payload is XOR'd.
 * CRC-16 (Modbus polynomial 0xA001) computed over obfuscated payload.
 *
 * Message flow:
 *   1. TCP connect -> server.growatt.com:5279
 *   2. PING (0x16) every 3 min
 *   3. ANNOUNCE (0x03) until ACKed
 *   4. DATA (0x04) every 5 min with inverter register values
 *   5. Handle IDENTIFY (0x19) and CONFIGURE (0x18) from server
 */

#include "GrowattCloud.h"
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
    , _unackedCount(0)
    , _announceAcked(false)
    , _packetsSent(0)
    , _packetsRecv(0)
    , _reconnects(0)
{
}

// ============================================================================
// Public API
// ============================================================================

void GrowattCloud::begin(const GrowattCloudConfig& config) {
    _config = config;
    if (_config.serverPort == 0) _config.serverPort = GROWATT_PORT_DEFAULT;
    if (_config.logIntervalMin == 0) _config.logIntervalMin = 5;
    if (_config.protocolId == 0) _config.protocolId = GROWATT_PROTO_ENC_V1;
    if (strlen(_config.serverHost) == 0) {
        strncpy(_config.serverHost, GROWATT_SERVER_DEFAULT, sizeof(_config.serverHost) - 1);
    }
    if (strlen(_config.fwVersion) == 0) {
        strncpy(_config.fwVersion, "1.7.7.7", sizeof(_config.fwVersion) - 1);
    }
    _state = GCS_DISCONNECTED;
    Serial.printf("[GrowattCloud] Initialized: server=%s:%d serial=%s proto=0x%04X\n",
                  _config.serverHost, _config.serverPort,
                  _config.dataloggerSerial, _config.protocolId);
}

void GrowattCloud::loop(const uint16_t* inputRegs, uint16_t numInputRegs,
                        const uint16_t* holdingRegs, uint16_t numHoldingRegs) {
    if (!_config.enabled) return;
    if (strlen(_config.dataloggerSerial) == 0) return;

    uint32_t now = millis();

    switch (_state) {
        case GCS_DISCONNECTED:
        case GCS_ERROR:
            if (now - _lastConnectAttempt >= GROWATT_CONNECT_TIMEOUT) {
                _connect();
            }
            break;

        case GCS_CONNECTING:
            if (_client.connected()) {
                _state = GCS_CONNECTED;
                _announceAcked = false;
                _unackedCount = 0;
                Serial.println("[GrowattCloud] TCP connected");
                // Send initial PING immediately
                uint16_t len = _buildPing(_txBuf);
                _sendPacket(_txBuf, len);
                _lastPing = now;
            } else if (now - _lastConnectAttempt >= GROWATT_CONNECT_TIMEOUT) {
                _state = GCS_ERROR;
            }
            break;

        case GCS_CONNECTED:
            // Send ANNOUNCE, wait for ACK
            if (now - _lastAnnounce >= GROWATT_ANNOUNCE_RETRY || _lastAnnounce == 0) {
                uint16_t len = _buildAnnounce(_txBuf, holdingRegs, numHoldingRegs);
                if (_sendPacket(_txBuf, len)) {
                    _lastAnnounce = now;
                }
            }
            // Check for server response
            _handleReceived();
            // Periodic PING
            if (now - _lastPing >= GROWATT_PING_INTERVAL) {
                uint16_t len = _buildPing(_txBuf);
                _sendPacket(_txBuf, len);
                _lastPing = now;
            }
            if (_announceAcked) {
                _state = GCS_ACTIVE;
                Serial.println("[GrowattCloud] ANNOUNCE ACKed, entering ACTIVE state");
            }
            break;

        case GCS_ANNOUNCED:
        case GCS_ACTIVE:
            // Check connection
            if (!_checkConnection()) {
                _disconnect();
                break;
            }
            // Handle incoming messages (IDENTIFY, CONFIGURE, ACKs)
            _handleReceived();
            // Periodic PING
            if (now - _lastPing >= GROWATT_PING_INTERVAL) {
                uint16_t len = _buildPing(_txBuf);
                _sendPacket(_txBuf, len);
                _lastPing = now;
            }
            // Periodic DATA report
            if (inputRegs && numInputRegs > 0) {
                uint32_t dataInterval = (uint32_t)_config.logIntervalMin * 60000UL;
                if (now - _lastDataSend >= dataInterval) {
                    uint16_t len = _buildData(_txBuf, inputRegs, numInputRegs);
                    if (_sendPacket(_txBuf, len)) {
                        _lastDataSend = now;
                    }
                }
            }
            // Check for too many unacked messages
            if (_unackedCount >= GROWATT_MAX_UNACKED) {
                Serial.println("[GrowattCloud] Too many unacked, reconnecting");
                _disconnect();
            }
            break;
    }
}

void GrowattCloud::reconnect() {
    _disconnect();
}

void GrowattCloud::setInverterSerial(const char* serial) {
    strncpy(_config.inverterSerial, serial, GROWATT_SERIAL_LEN);
    _config.inverterSerial[GROWATT_SERIAL_LEN] = '\0';
}

// ============================================================================
// Connection Management
// ============================================================================

void GrowattCloud::_connect() {
    _lastConnectAttempt = millis();
    Serial.printf("[GrowattCloud] Connecting to %s:%d...\n",
                  _config.serverHost, _config.serverPort);

    if (_client.connect(_config.serverHost, _config.serverPort)) {
        _state = GCS_CONNECTED;
        _announceAcked = false;
        _unackedCount = 0;
        _lastAnnounce = 0;
        _reconnects++;
        // Send initial PING
        uint16_t len = _buildPing(_txBuf);
        _sendPacket(_txBuf, len);
        _lastPing = millis();
    } else {
        _state = GCS_ERROR;
        Serial.println("[GrowattCloud] Connection failed");
    }
}

void GrowattCloud::_disconnect() {
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

    // CRC over obfuscated payload
    uint16_t crc = _calcCRC16(buf, GROWATT_HEADER_LEN + dataLen);
    buf[GROWATT_HEADER_LEN + dataLen] = (crc >> 8) & 0xFF;
    buf[GROWATT_HEADER_LEN + dataLen + 1] = crc & 0xFF;

    return totalLen;
}

/**
 * ANNOUNCE (0x03): Device announcement with inverter info
 * Stock firmware sends identical 255-byte payload structure as DATA,
 * just with func code 0x03 instead of 0x04.
 * Register data area contains holding register values (or zeros).
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

    // Bytes 71-160: Holding registers 0-44 as sequential uint16 BE (or zeros)
    for (uint16_t i = 0; i < 45; i++) {
        uint16_t val = (holdingRegs && i < numHoldingRegs) ? holdingRegs[i] : 0;
        p[71 + i * 2]     = (val >> 8) & 0xFF;
        p[71 + i * 2 + 1] = val & 0xFF;
    }

    // Block 2 descriptor embedded at register positions 45-46
    p[161] = 0x00; p[162] = 45;   // Block 2 start register = 45
    p[163] = 0x00; p[164] = 89;   // Block 2 end register = 89

    // Bytes 165-250: Holding registers 47-89 as sequential uint16 BE (or zeros)
    for (uint16_t i = 47; i < 90; i++) {
        uint16_t val = (holdingRegs && i < numHoldingRegs) ? holdingRegs[i] : 0;
        uint16_t offset = 165 + (i - 47) * 2;
        p[offset]     = (val >> 8) & 0xFF;
        p[offset + 1] = val & 0xFF;
    }

    // Bytes 251-254: Zero padding (already zeroed by memset)

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

    return payloadOffset + payloadLen + 2; // 8 + 255 + 2 = 265
}

/**
 * DATA (0x04): Periodic inverter telemetry report
 * Verified stock firmware format: 265 bytes total (8 header + 255 payload + 2 CRC)
 * Payload layout (255 bytes, fixed size):
 *   [0-29]    Datalogger serial (30B NUL-padded)
 *   [30-59]   Inverter serial (30B NUL-padded)
 *   [60-65]   Timestamp (6x uint8: Y-2000, M, D, H, M, S)
 *   [66]      Inverter type = 0x02
 *   [67-68]   Block 1 start register = 0 (uint16 BE)
 *   [69-70]   Block 1 end register = 44 (uint16 BE)
 *   [71-160]  FC04 input registers 0-44 (45 x 2 = 90 bytes, uint16 BE)
 *   [161-162] Block 2 start register = 45 (embedded at reg positions 45-46)
 *   [163-164] Block 2 end register = 89 (embedded at reg positions 45-46)
 *   [165-250] FC04 input registers 47-89 (43 x 2 = 86 bytes, uint16 BE)
 *   [251-254] Zero padding
 * data_len field = 257 (255 payload + 2 for unit_id + func_code)
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

    // Bytes 71-160: Input registers 0-44 as sequential uint16 BE (45 regs = 90 bytes)
    for (uint16_t i = 0; i < 45; i++) {
        uint16_t val = (i < numInputRegs) ? inputRegs[i] : 0;
        p[71 + i * 2]     = (val >> 8) & 0xFF;
        p[71 + i * 2 + 1] = val & 0xFF;
    }
    // Note: At byte offsets 161-164 (register positions 45 and 46 in the stream),
    // the stock firmware embeds block 2 descriptor values (45 and 89).
    // These occupy the same positions as inputRegs[45] and inputRegs[46] would.
    p[161] = 0x00; p[162] = 45;   // Block 2 start register = 45
    p[163] = 0x00; p[164] = 89;   // Block 2 end register = 89

    // Bytes 165-250: Input registers 47-89 as sequential uint16 BE (43 regs = 86 bytes)
    for (uint16_t i = 47; i < 90; i++) {
        uint16_t val = (i < numInputRegs) ? inputRegs[i] : 0;
        uint16_t offset = 165 + (i - 47) * 2;
        p[offset]     = (val >> 8) & 0xFF;
        p[offset + 1] = val & 0xFF;
    }

    // Bytes 251-254: Zero padding (already zeroed by memset)

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

    return payloadOffset + payloadLen + 2; // 8 + 255 + 2 = 265
}

// ============================================================================
// Receive Handler
// ============================================================================

void GrowattCloud::_handleReceived() {
    if (!_client.available()) return;

    int len = _readPacket(_rxBuf, GROWATT_MAX_PACKET);
    if (len < GROWATT_HEADER_LEN) return;

    _packetsRecv++;

    uint8_t funcCode = _rxBuf[7];

    // Decrypt payload if encrypted protocol
    uint16_t protoId = (_rxBuf[2] << 8) | _rxBuf[3];
    if (protoId == GROWATT_PROTO_ENC_V1 || protoId == GROWATT_PROTO_ENC_V2) {
        _xorDecrypt(_rxBuf, GROWATT_HEADER_LEN, len - GROWATT_HEADER_LEN);
    }

    switch (funcCode) {
        case GROWATT_FUNC_PING:
            // PING echo from server - connection is alive
            break;

        case GROWATT_FUNC_ANNOUNCE:
            // ACK for our ANNOUNCE
            _handleAck(GROWATT_FUNC_ANNOUNCE);
            break;

        case GROWATT_FUNC_DATA:
            // ACK for our DATA
            _handleAck(GROWATT_FUNC_DATA);
            break;

        case GROWATT_FUNC_IDENTIFY:
            // Server is querying our configuration
            _handleIdentify(_rxBuf, len);
            break;

        case GROWATT_FUNC_CONFIGURE:
            // Server is pushing configuration changes
            _handleConfigure(_rxBuf, len);
            break;

        default:
            Serial.printf("[GrowattCloud] Unknown func 0x%02X, len=%d\n", funcCode, len);
            break;
    }
}

void GrowattCloud::_handleAck(uint8_t funcCode) {
    if (_unackedCount > 0) _unackedCount--;

    if (funcCode == GROWATT_FUNC_ANNOUNCE) {
        _announceAcked = true;
        Serial.println("[GrowattCloud] ANNOUNCE ACK received");
    } else if (funcCode == GROWATT_FUNC_DATA) {
        Serial.println("[GrowattCloud] DATA ACK received");
    }
}

/**
 * Handle IDENTIFY (0x19) queries from server.
 * Server asks for specific config items; we must respond honestly.
 *
 * CRITICAL: For config item 0x13 (server address), ALWAYS respond
 * with "server.growatt.com" even if we're running locally. Otherwise
 * the server force-reconfigures and reboots us.
 */
void GrowattCloud::_handleIdentify(const uint8_t* data, uint16_t len) {
    if (len < GROWATT_HEADER_LEN + GROWATT_SERIAL_LEN + 4) return;

    uint16_t payloadStart = GROWATT_HEADER_LEN + GROWATT_SERIAL_LEN;
    uint16_t configItem = (data[payloadStart] << 8) | data[payloadStart + 1];

    Serial.printf("[GrowattCloud] IDENTIFY query: config item 0x%04X\n", configItem);

    // Build response
    uint16_t pos = GROWATT_HEADER_LEN;

    // Echo datalogger serial
    _writeSerial(_txBuf + pos, _config.dataloggerSerial);
    pos += GROWATT_SERIAL_LEN;

    // Config item
    _txBuf[pos++] = (configItem >> 8) & 0xFF;
    _txBuf[pos++] = configItem & 0xFF;

    // Value depends on config item
    switch (configItem) {
        case GROWATT_CFG_INTERVAL: {
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x01; // length = 1
            _txBuf[pos++] = _config.logIntervalMin;
            break;
        }
        case GROWATT_CFG_ADDR_MIN: {
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x01;
            _txBuf[pos++] = 1; // Modbus addr min
            break;
        }
        case GROWATT_CFG_ADDR_MAX: {
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x01;
            _txBuf[pos++] = 1; // Modbus addr max (single inverter)
            break;
        }
        case GROWATT_CFG_DATALOGGER_ID: {
            uint8_t slen = strlen(_config.dataloggerSerial);
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, _config.dataloggerSerial, slen);
            pos += slen;
            break;
        }
        case GROWATT_CFG_LOCAL_IP: {
            String ip = WiFi.localIP().toString();
            uint8_t slen = ip.length();
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, ip.c_str(), slen);
            pos += slen;
            break;
        }
        case GROWATT_CFG_LOCAL_PORT: {
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x04;
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x00;
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x00;
            break;
        }
        case GROWATT_CFG_MAC: {
            String mac = WiFi.macAddress(); // "AA:BB:CC:DD:EE:FF"
            uint8_t slen = mac.length();
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, mac.c_str(), slen);
            pos += slen;
            break;
        }
        case GROWATT_CFG_SERVER_LEN: {
            // Length of server hostname
            uint8_t slen = strlen(GROWATT_SERVER_DEFAULT);
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x01;
            _txBuf[pos++] = slen;
            break;
        }
        case GROWATT_CFG_SERVER_PORT: {
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x04;
            uint32_t port = GROWATT_PORT_DEFAULT;
            _txBuf[pos++] = (port >> 24) & 0xFF;
            _txBuf[pos++] = (port >> 16) & 0xFF;
            _txBuf[pos++] = (port >> 8) & 0xFF;
            _txBuf[pos++] = port & 0xFF;
            break;
        }
        case GROWATT_CFG_SERVER_ADDR: {
            // CRITICAL: Always respond with the official server address!
            // If we respond with anything else, server pushes a reconfig + reboot.
            const char* official = GROWATT_SERVER_DEFAULT;
            uint8_t slen = strlen(official);
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, official, slen);
            pos += slen;
            break;
        }
        case GROWATT_CFG_FW_VERSION: {
            uint8_t slen = strlen(_config.fwVersion);
            _txBuf[pos++] = 0x00; _txBuf[pos++] = slen;
            memcpy(_txBuf + pos, _config.fwVersion, slen);
            pos += slen;
            break;
        }
        default: {
            // Unknown config item - respond with empty
            _txBuf[pos++] = 0x00; _txBuf[pos++] = 0x00;
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

    _sendPacket(_txBuf, pos);
}

/**
 * Handle CONFIGURE (0x18) from server.
 * Always ACK (0x00) to prevent server from retrying.
 * Ignore actual config changes since we manage our own config.
 *
 * Special case: 0x20 = reboot command. We ACK but do NOT reboot.
 */
void GrowattCloud::_handleConfigure(const uint8_t* data, uint16_t len) {
    if (len < GROWATT_HEADER_LEN + GROWATT_SERIAL_LEN + 4) return;

    uint16_t payloadStart = GROWATT_HEADER_LEN + GROWATT_SERIAL_LEN;
    uint16_t configItem = (data[payloadStart] << 8) | data[payloadStart + 1];

    Serial.printf("[GrowattCloud] CONFIGURE push: item 0x%04X (ACKing, ignoring)\n",
                  configItem);

    // Build ACK response: [header][serial][config_item][0x00 0x01][0x00]
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

    _sendPacket(_txBuf, pos);
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

bool GrowattCloud::_sendPacket(uint8_t* buf, uint16_t len) {
    if (!_client.connected()) return false;

    size_t written = _client.write(buf, len);
    if (written == len) {
        _packetsSent++;
        _unackedCount++;
        return true;
    }
    Serial.printf("[GrowattCloud] Send failed: wrote %d/%d\n", written, len);
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
    if (headerRead < GROWATT_HEADER_LEN) return headerRead;

    // Extract data length from header
    uint16_t dataLen = (buf[4] << 8) | buf[5];
    if (dataLen > maxLen - GROWATT_HEADER_LEN) {
        // Packet too large, drain and discard
        while (_client.available()) _client.read();
        return GROWATT_HEADER_LEN;
    }

    // Read remaining data
    int dataRead = 0;
    start = millis();
    while (dataRead < dataLen && millis() - start < GROWATT_READ_TIMEOUT) {
        if (_client.available()) {
            buf[GROWATT_HEADER_LEN + dataRead++] = _client.read();
        } else {
            delay(1);
        }
    }

    return GROWATT_HEADER_LEN + dataRead;
}
