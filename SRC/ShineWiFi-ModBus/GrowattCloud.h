/**
 * GrowattCloud.h - Growatt Cloud Protocol Sender for OpenInverterGateway
 *
 * Implements the Growatt proprietary TCP protocol (port 5279) to send
 * inverter data to server.growatt.com while simultaneously publishing
 * to MQTT/Prometheus locally. This enables dual-mode operation:
 * local monitoring + Growatt app/cloud access.
 *
 * Protocol details reverse-engineered from stock ShineWiFi-S firmware
 * and community documentation (Grott, nwf, sciurius).
 *
 * Author: OpenInverterGateway contributors
 * Date: 2026-05-15
 * License: MIT
 */

#ifndef GROWATT_CLOUD_H
#define GROWATT_CLOUD_H

#include <Arduino.h>
#include <WiFiClient.h>

// --- Protocol Constants ---
#define GROWATT_SERVER_DEFAULT    "server.growatt.com"
#define GROWATT_PORT_DEFAULT      5279

// Protocol IDs (bytes 2-3 of header)
#define GROWATT_PROTO_PLAIN       0x0000  // Modbus standard, no encryption
#define GROWATT_PROTO_V3          0x0002  // Growatt v3.x, no encryption
#define GROWATT_PROTO_ENC_V1      0x0005  // Growatt encrypted v1 (XOR)
#define GROWATT_PROTO_ENC_V2      0x0006  // Growatt encrypted v2 (XOR)

// Function codes (byte 7 of header)
#define GROWATT_FUNC_ANNOUNCE     0x03   // DATA3: device announcement
#define GROWATT_FUNC_DATA         0x04   // DATA4: periodic telemetry
#define GROWATT_FUNC_PING         0x16   // Keepalive heartbeat
#define GROWATT_FUNC_CONFIGURE    0x18   // Server pushes config
#define GROWATT_FUNC_IDENTIFY     0x19   // Server queries config
#define GROWATT_FUNC_REBOOT       0x20   // Server reboot command
#define GROWATT_FUNC_BUFFERED     0x50   // Buffered data report
#define GROWATT_FUNC_5D           0x5D   // Unknown/firmware update

// Identify config items (for responding to server queries)
#define GROWATT_CFG_INTERVAL      0x04   // Log interval / protocol version
#define GROWATT_CFG_ADDR_MIN      0x05   // Modbus address range min
#define GROWATT_CFG_ADDR_MAX      0x06   // Modbus address range max
#define GROWATT_CFG_SERVER_PORT_U16 0x07 // Server port (uint16)
#define GROWATT_CFG_DATALOGGER_ID 0x08   // Datalogger serial
#define GROWATT_CFG_INVERTER_ID   0x09   // Inverter serial
#define GROWATT_CFG_LOCAL_IP      0x0E   // Local IP address
#define GROWATT_CFG_NETMASK       0x0F   // Netmask
#define GROWATT_CFG_MAC           0x10   // MAC address
#define GROWATT_CFG_SERVER_ADDR   0x11   // Server address
#define GROWATT_CFG_SERVER_PORT   0x12   // Server port (string)
#define GROWATT_CFG_SERVER_ADDR2  0x13   // Server address (alt, ENFORCED!)
#define GROWATT_CFG_FW_VERSION    0x15   // Firmware version string
#define GROWATT_CFG_TIME          0x1F   // Current time
#define GROWATT_CFG_WIFI_SSID     0x30   // WiFi SSID

// Timing (milliseconds)
#define GROWATT_PING_INTERVAL     30000   // 30 seconds (matches stock firmware)
#define GROWATT_DATA_INTERVAL     300000  // 5 minutes (configurable)
#define GROWATT_ANNOUNCE_RETRY    30000   // 30 seconds until ACKed
#define GROWATT_CONNECT_TIMEOUT   10000   // TCP connect timeout
#define GROWATT_READ_TIMEOUT      5000    // TCP read timeout
#define GROWATT_MAX_UNACKED       15      // Drop connection after N unacked
#define GROWATT_IDENTIFY_WAIT     8000    // Wait for IDENTIFY after PING (ms)
#define GROWATT_SILENT_TIMEOUT    90000   // No RX at all since connect -> cycle session
#define GROWATT_RX_TIMEOUT        300000  // RX stalled mid-session -> cycle session
#define GROWATT_RECONNECT_DELAY   30000   // Base reconnect delay, doubled per silent session

// Buffer sizes
#define GROWATT_SERIAL_LEN        30      // Serial field width (NUL-padded)
#define GROWATT_HEADER_LEN        8       // Protocol header size
#define GROWATT_MAX_PACKET        512     // Max packet size
#define GROWATT_TIMESTAMP_LEN     6       // 6 single bytes: Y-2000, M, D, H, M, S

// XOR encryption mask
static const uint8_t GROWATT_XOR_MASK[] = { 0x47, 0x72, 0x6F, 0x77, 0x61, 0x74, 0x74 };
#define GROWATT_XOR_MASK_LEN      7

// Maximum number of raw Modbus registers for DATA/ANNOUNCE packets
#define GROWATT_MAX_INPUT_REGS    90
#define GROWATT_MAX_HOLDING_REGS  90

// --- Structures ---

struct GrowattCloudConfig {
    char     serverHost[64];
    uint16_t serverPort;
    char     dataloggerSerial[GROWATT_SERIAL_LEN + 1]; // Read from config portal
    char     inverterSerial[GROWATT_SERIAL_LEN + 1];   // Read from inverter via Modbus
    char     fwVersion[16];
    uint8_t  logIntervalMin;      // Data report interval in minutes
    uint16_t protocolId;          // 0x0006 for encrypted v2
    bool     enabled;             // Enable/disable cloud sending
};

// Connection state machine
enum GrowattCloudState {
    GCS_DISCONNECTED,
    GCS_CONNECTING,
    GCS_CONNECTED,       // TCP up, initial PING sent
    GCS_PING_WAIT,       // Waiting for IDENTIFY queries after PING
    GCS_ANNOUNCED,       // ANNOUNCE sent, waiting for ACK
    GCS_ACTIVE,          // ACK received, sending periodic DATA
    GCS_ERROR
};

class GrowattCloud {
public:
    GrowattCloud();

    /**
     * Initialize with configuration.
     * Call once in setup() after reading config from portal/EEPROM.
     */
    void begin(const GrowattCloudConfig& config);

    /**
     * Call in loop(). Handles connection, ping, announce, data sending.
     * Pass current inverter register data for periodic reports.
     *
     * @param inputRegs    Array of raw input register values indexed by MODBUS ADDRESS
     * @param numInputRegs Number of input registers (highest address + 1)
     * @param holdingRegs  Array of raw holding register values indexed by MODBUS ADDRESS
     * @param numHoldingRegs Number of holding registers (highest address + 1)
     */
    void loop(const uint16_t* inputRegs, uint16_t numInputRegs,
              const uint16_t* holdingRegs = nullptr, uint16_t numHoldingRegs = 0);

    /**
     * Check if connected and active.
     */
    bool isConnected() const { return _state == GCS_ACTIVE || _state == GCS_ANNOUNCED; }

    /**
     * Get current state for debugging.
     */
    GrowattCloudState getState() const { return _state; }

    /**
     * Get state name for debugging.
     */
    const char* getStateName() const;

    /**
     * Force reconnection.
     */
    void reconnect();

    /**
     * Update inverter serial (discovered via Modbus after boot).
     */
    void setInverterSerial(const char* serial);

    /**
     * Check if inverter serial has been set.
     */
    bool hasInverterSerial() const { return strlen(_config.inverterSerial) > 0; }

    /**
     * Get stats for web UI / debugging.
     */
    uint32_t getPacketsSent() const { return _packetsSent; }
    uint32_t getPacketsRecv() const { return _packetsRecv; }
    uint32_t getReconnects() const { return _reconnects; }
    uint32_t getLastSendTime() const { return _lastDataSend; }

private:
    // --- Connection management ---
    void _connect();
    void _disconnect();
    bool _checkConnection();

    // --- Protocol message builders ---
    uint16_t _buildPing(uint8_t* buf);
    uint16_t _buildAnnounce(uint8_t* buf, const uint16_t* holdingRegs, uint16_t numHoldingRegs);
    uint16_t _buildData(uint8_t* buf, const uint16_t* inputRegs, uint16_t numInputRegs);
    uint16_t _buildGenericAck(uint8_t* buf, uint8_t funcCode);

    // --- Protocol message handlers ---
    void _handleReceived();
    void _handleAck(uint8_t funcCode);
    void _handleIdentify(const uint8_t* data, uint16_t len);
    void _handleConfigure(const uint8_t* data, uint16_t len);

    // --- Header and encryption ---
    void _writeHeader(uint8_t* buf, uint16_t transId, uint16_t protoId,
                      uint16_t dataLen, uint8_t unitId, uint8_t funcCode);
    void _xorEncrypt(uint8_t* data, uint16_t offset, uint16_t len);
    void _xorDecrypt(uint8_t* data, uint16_t offset, uint16_t len);
    uint16_t _calcCRC16(const uint8_t* data, uint16_t len);
    void _writeSerial(uint8_t* buf, const char* serial);
    void _writeTimestamp(uint8_t* buf);

    // --- Send/receive helpers ---
    bool _sendPacket(uint8_t* buf, uint16_t len, const char* label);
    int  _readPacket(uint8_t* buf, uint16_t maxLen);

    // --- Logging helper ---
    void _logHex(const char* prefix, const uint8_t* data, uint16_t len, uint16_t maxBytes = 32);

    // --- State ---
    WiFiClient         _client;
    GrowattCloudConfig _config;
    GrowattCloudState  _state;
    uint16_t           _transactionId;
    uint32_t           _lastPing;
    uint32_t           _lastDataSend;
    uint32_t           _lastAnnounce;
    uint32_t           _lastConnectAttempt;
    uint32_t           _pingWaitStart;    // When PING_WAIT state entered
    uint8_t            _unackedCount;
    bool               _announceAcked;

    // --- Stats ---
    uint32_t           _packetsSent;
    uint32_t           _packetsRecv;
    uint32_t           _reconnects;
    uint32_t           _lastRecvTime;     // millis() of last valid RX (0 = none this session)
    uint32_t           _connectTime;      // millis() when current session connected
    uint8_t            _silentSessions;   // consecutive sessions with zero RX

    // --- Buffers ---
    uint8_t            _txBuf[GROWATT_MAX_PACKET];
    uint8_t            _rxBuf[GROWATT_MAX_PACKET];
};

#endif // GROWATT_CLOUD_H
