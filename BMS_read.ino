/*
 * JK/Daly BMS BLE Reader for ESP32  --  D2 Protocol (verified)
 * ================================================================
 * This version uses the legacy "D2" Daly Modbus-RTU protocol, NOT the P81
 * protocol from the earlier version of this code. The D2 protocol returns
 * ALL battery data (voltage, current, SOC, capacity, temps, cycles, MOS
 * state) in ONE combined response, instead of three separate requests.
 *
 * WHY THIS REPLACES THE PREVIOUS VERSION:
 *   The P81-based code had wrong offsets for current, SOC, and capacity --
 *   confirmed wrong by the user (capacity showed 30Ah instead of their
 *   real 100Ah pack, and SOC was drifting like a tick counter, not a
 *   real percentage).
 *
 *   The field offsets below come from the Home Assistant "batmon" BMS
 *   integration (a working, production Daly BMS driver) and have been
 *   independently verified against:
 *     1. A live capture from the user's actual BMS (3 frames, all CRC-valid)
 *     2. Cross-checked cell voltage sum vs decoded pack voltage (match)
 *     3. Cross-checked SOC% x rated_capacity = remaining_capacity_Ah,
 *        which resolves to EXACTLY 100.0 Ah -- matching the Smart BMS Pro
 *        app's displayed 100Ah rating. This is the strongest evidence:
 *        an independently-derived value matching a user-confirmed fact.
 *
 * Hardware:  Any ESP32 board (ESP32, ESP32-S3, ESP32-C3)
 * Library:   Built-in ESP32 BLE library (BLEDevice.h) -- no extra install.
 *
 * ─── Protocol reference ────────────────────────────────────────────────────
 * Service  0000fff0-0000-1000-8000-00805f9b34fb
 *   RX     0000fff1-...  Notify           (BMS -> ESP32)
 *   TX     0000fff2-...  WriteWithoutResp (ESP32 -> BMS)
 *
 * Request (8 bytes, D2 protocol):
 *   [0]   0xD2        D2 protocol marker (NOT 0x81 -- that's the P81 variant)
 *   [1]   0x03        Read Holding Registers
 *   [2-3] uint16 BE   Start register address (always 0x0000 for status)
 *   [4-5] uint16 BE   Register count (80 registers = 160 bytes of data)
 *   [6-7] uint16 LE   CRC-16/Modbus
 *
 * Verified request frame:  D2 03 00 00 00 50 56 55
 *
 * Response (notification from RX):
 *   [0]   0xD2        Slave echo
 *   [1]   0x03        Function echo
 *   [2]   uint8       Byte count (160 for count=80)
 *   [3..162]          Register data (big-endian, byte-offset addressed)
 *   [163-164]         CRC-16/Modbus (little-endian)
 *
 * VERIFIED FIELD OFFSETS (relative to start of the 160-byte data payload,
 * i.e. payload[0] = response_frame[3]):
 *
 *   payload[0..7]    cell voltages 1..4   uint16 BE  mV
 *   payload[64]      temperature 1        uint16 BE  raw-40 = C
 *   payload[80]      total pack voltage   uint16 BE  x0.1 = V
 *   payload[82]      current              uint16 BE  (raw-30000) x0.1 = A
 *                                          (+ve = charging, -ve = discharging)
 *   payload[84]      SOC                  uint16 BE  x0.1 = %
 *   payload[86]      max cell voltage     uint16 BE  mV
 *   payload[88]      min cell voltage     uint16 BE  mV
 *   payload[90]      max battery temp     uint16 BE  raw-40 = C
 *   payload[92]      min battery temp     uint16 BE  raw-40 = C
 *   payload[96]      remaining capacity   uint16 BE  x0.1 = Ah
 *   payload[98]      cell count           uint16 BE
 *   payload[100]     temp sensor count    uint16 BE
 *   payload[102]     charging cycles      uint16 BE
 *   payload[110]     average cell voltage uint16 BE  mV
 *   payload[112]     delta cell voltage   uint16 BE  mV
 *   payload[20]      MOS status byte      uint8
 *                       0 = both off, 1 = charge MOS on,
 *                       2 = discharge MOS on, 3 = both on
 *
 * Rated capacity is NOT directly present as a single field in this frame;
 * it's derived as: rated_Ah = remaining_Ah / (SOC% / 100)
 * (This matched the user's 100Ah pack exactly when verified.)
 *
 * Usage:
 *   1. Set BMS_ADDRESS to your BMS MAC address.
 *   2. Flash to ESP32, open Serial Monitor at 115200 baud.
 */

#include <BLEDevice.h>
#include <BLEClient.h>
#include <BLEUtils.h>

// ── Configuration ─────────────────────────────────────────────────────────────
#define BMS_ADDRESS        "70:C1:45:30:11:52"
#define POLL_INTERVAL_MS   2000
#define RESPONSE_WAIT_MS   600
#define CONNECT_TIMEOUT_MS 10000

// ── GATT UUIDs ────────────────────────────────────────────────────────────────
static BLEUUID SERVICE_UUID("0000fff0-0000-1000-8000-00805f9b34fb");
static BLEUUID CHAR_RX_UUID("0000fff1-0000-1000-8000-00805f9b34fb");
static BLEUUID CHAR_TX_UUID("0000fff2-0000-1000-8000-00805f9b34fb");

// ── D2 protocol request frame (verified: returns 165-byte response) ──────────
// D2 03 00 00 00 50 56 55  =  addr=0x0000, count=80 registers (160 bytes)
static const uint8_t REQ_D2_STATUS[8] = {0xD2,0x03,0x00,0x00,0x00,0x50,0x56,0x55};

// ── BMS data structure ────────────────────────────────────────────────────────
struct BMSData {
    float    cell_v[4];           // cell voltages V (only first 4 populated)
    float    total_voltage_v;
    float    current_a;           // +ve = charging, -ve = discharging
    float    soc_pct;
    float    remaining_cap_ah;
    float    rated_cap_ah;        // derived: remaining / (soc/100)
    float    max_cell_v;
    float    min_cell_v;
    int8_t   max_bat_temp_c;
    int8_t   min_bat_temp_c;
    int8_t   temp_c[4];           // up to 4 temp sensors
    uint8_t  temp_count;
    uint16_t cell_count;
    uint16_t cycles;
    float    avg_cell_v;
    uint16_t delta_cell_mv;
    uint8_t  mos_byte;
    bool     charge_mos;
    bool     discharge_mos;
    bool     valid;
};

static BMSData bms;

// ── Modbus helpers ────────────────────────────────────────────────────────────
static uint16_t crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : crc >> 1;
    }
    return crc;
}

static uint16_t u16be(const uint8_t* buf, size_t off) {
    return ((uint16_t)buf[off] << 8) | buf[off + 1];
}

static bool check_response(const uint8_t* buf, size_t len) {
    if (len < 5)        return false;
    if (buf[0] != 0xD2)  return false;   // D2 protocol slave echo
    if (buf[1] != 0x03)  return false;
    uint8_t  n = buf[2];
    if (len < (size_t)(3 + n + 2)) return false;
    uint16_t stored   = (uint16_t)buf[3 + n] | ((uint16_t)buf[3 + n + 1] << 8);
    uint16_t computed = crc16(buf, 3 + n);
    return stored == computed;
}

// ── Decoder (verified offsets) ────────────────────────────────────────────────
static void decode_d2_status(const uint8_t* payload, size_t len) {
    if (len < 160) {
        Serial.printf("[WARN] D2 payload too short: %u bytes (need 160)\n", len);
        return;
    }

    for (int i = 0; i < 4; i++)
        bms.cell_v[i] = u16be(payload, i * 2) * 0.001f;

    bms.total_voltage_v  = u16be(payload, 80) * 0.1f;
    bms.current_a        = ((int32_t)u16be(payload, 82) - 30000) * 0.1f;
    bms.soc_pct           = u16be(payload, 84) * 0.1f;
    bms.max_cell_v        = u16be(payload, 86) * 0.001f;
    bms.min_cell_v        = u16be(payload, 88) * 0.001f;
    bms.max_bat_temp_c    = (int8_t)(u16be(payload, 90) - 40);
    bms.min_bat_temp_c    = (int8_t)(u16be(payload, 92) - 40);
    bms.remaining_cap_ah  = u16be(payload, 96) * 0.1f;
    bms.cell_count        = u16be(payload, 98);
    bms.temp_count        = (uint8_t)min((int)u16be(payload, 100), 4);
    bms.cycles            = u16be(payload, 102);
    bms.avg_cell_v        = u16be(payload, 110) * 0.001f;
    bms.delta_cell_mv     = u16be(payload, 112);
    bms.mos_byte          = payload[20];
    bms.charge_mos         = (bms.mos_byte == 1 || bms.mos_byte == 3);
    bms.discharge_mos      = (bms.mos_byte == 2 || bms.mos_byte == 3);

    // Temperatures: payload[64 + i*2], raw-40 = C, skip 0xFF sentinel
    for (uint8_t i = 0; i < bms.temp_count; i++) {
        uint16_t raw = u16be(payload, 64 + i * 2);
        bms.temp_c[i] = (raw == 0x00FF) ? -128 : (int8_t)(raw - 40);
    }

    // Rated capacity derived from remaining_Ah / (SOC% / 100)
    // (no separate "rated capacity" field found in this frame layout)
    if (bms.soc_pct > 0.1f)
        bms.rated_cap_ah = bms.remaining_cap_ah / (bms.soc_pct / 100.0f);
    else
        bms.rated_cap_ah = 0.0f;

    bms.valid = true;

    Serial.printf("[D2] %.1fV  %+.1fA  SOC=%.1f%%  remain=%.1fAh  "
                  "rated~=%.1fAh  cycles=%u  cells=%u  "
                  "max=%.3fV  min=%.3fV  mos=%u(chg=%d,dis=%d)\n",
                  bms.total_voltage_v, bms.current_a, bms.soc_pct,
                  bms.remaining_cap_ah, bms.rated_cap_ah, bms.cycles,
                  bms.cell_count, bms.max_cell_v, bms.min_cell_v,
                  bms.mos_byte, bms.charge_mos, bms.discharge_mos);
}

// ── BLE notification buffer ───────────────────────────────────────────────────
static uint8_t  rx_buf[256];
static uint16_t rx_len = 0;

static void process_rx_buffer() {
    while (rx_len >= 5) {
        if (rx_buf[0] != 0xD2 || rx_buf[1] != 0x03) {
            memmove(rx_buf, rx_buf + 1, --rx_len);
            continue;
        }
        uint8_t  n    = rx_buf[2];
        uint16_t need = 3 + n + 2;
        if (rx_len < need) break;

        if (!check_response(rx_buf, need)) {
            Serial.println("[WARN] CRC mismatch - discarding frame");
            memmove(rx_buf, rx_buf + 1, --rx_len);
            continue;
        }

        decode_d2_status(rx_buf + 3, n);

        rx_len -= need;
        if (rx_len > 0)
            memmove(rx_buf, rx_buf + need, rx_len);
    }
}

// ── BLE client ────────────────────────────────────────────────────────────────
static BLEClient*               ble_client   = nullptr;
static BLERemoteCharacteristic* char_rx      = nullptr;
static BLERemoteCharacteristic* char_tx      = nullptr;
static volatile bool            connected    = false;
static volatile bool            notify_ready = false;

static void onNotify(BLERemoteCharacteristic*, uint8_t* data, size_t length, bool) {
    size_t space = sizeof(rx_buf) - rx_len;
    if (length > space) { rx_len = 0; space = sizeof(rx_buf); }
    size_t to_copy = (length < space) ? length : space;
    memcpy(rx_buf + rx_len, data, to_copy);
    rx_len += (uint16_t)to_copy;
    notify_ready = true;
}

class ClientCallbacks : public BLEClientCallbacks {
    void onConnect(BLEClient*) override { Serial.println("[BLE] Connected."); connected = true; }
    void onDisconnect(BLEClient*) override {
        Serial.println("[BLE] Disconnected. Will reconnect...");
        connected = false; notify_ready = false; rx_len = 0;
    }
};
static ClientCallbacks clientCallbacks;

static bool ble_connect() {
    Serial.printf("[BLE] Connecting to %s ...\n", BMS_ADDRESS);

    if (ble_client != nullptr) {
        if (ble_client->isConnected()) ble_client->disconnect();
        delete ble_client;
        ble_client = nullptr;
    }

    ble_client = BLEDevice::createClient();
    ble_client->setClientCallbacks(&clientCallbacks);

    if (!ble_client->connect(BLEAddress(BMS_ADDRESS))) {
        Serial.println("[BLE] Connection failed.");
        return false;
    }

    BLERemoteService* svc = ble_client->getService(SERVICE_UUID);
    if (!svc) { Serial.println("[BLE] fff0 service not found."); ble_client->disconnect(); return false; }

    char_rx = svc->getCharacteristic(CHAR_RX_UUID);
    if (!char_rx || !char_rx->canNotify()) {
        Serial.println("[BLE] fff1 notify char not found."); ble_client->disconnect(); return false;
    }

    char_tx = svc->getCharacteristic(CHAR_TX_UUID);
    if (!char_tx || !char_tx->canWriteNoResponse()) {
        Serial.println("[BLE] fff2 write char not found."); ble_client->disconnect(); return false;
    }

    char_rx->registerForNotify(onNotify);
    Serial.println("[BLE] Subscribed, settling...");
    delay(1000);
    return true;
}

static void send_request() {
    if (!connected || !char_tx) return;
    char_tx->writeValue((uint8_t*)REQ_D2_STATUS, 8, false);
}

// ── Print snapshot ────────────────────────────────────────────────────────────
static void print_bms() {
    if (!bms.valid) return;

    Serial.println("==================================================================");
    Serial.printf("  C1:%.3fV  C2:%.3fV  C3:%.3fV  C4:%.3fV\n",
                  bms.cell_v[0], bms.cell_v[1], bms.cell_v[2], bms.cell_v[3]);

    const char* status = bms.current_a > 0.05f ? "Charging" :
                         bms.current_a < -0.05f ? "Discharging" : "Idle";

    Serial.printf("  Pack:   %.3fV    I: %+.2fA  (%s)    P: %+.1fW\n",
                  bms.total_voltage_v, bms.current_a, status,
                  bms.total_voltage_v * bms.current_a);

    Serial.printf("  SOC:    %.1f%%    Remain: %.1fAh    Rated~: %.1fAh    Cycles: %u\n",
                  bms.soc_pct, bms.remaining_cap_ah, bms.rated_cap_ah, bms.cycles);

    Serial.printf("  Max: %.3fV    Min: %.3fV    Avg: %.3fV    Delta: %u mV\n",
                  bms.max_cell_v, bms.min_cell_v, bms.avg_cell_v, bms.delta_cell_mv);

    Serial.printf("  MOS:  CHG=%s  DIS=%s  (raw=%u)\n",
                  bms.charge_mos ? "ON " : "off",
                  bms.discharge_mos ? "ON " : "off",
                  bms.mos_byte);

    Serial.print("  Temps:  ");
    Serial.printf("BatMax:%dC  BatMin:%dC  ", bms.max_bat_temp_c, bms.min_bat_temp_c);
    for (uint8_t i = 0; i < bms.temp_count; i++) {
        if (bms.temp_c[i] != -128)
            Serial.printf("T%u:%dC  ", i + 1, bms.temp_c[i]);
    }
    Serial.println();
    Serial.println("==================================================================");
}

// ── Arduino setup & loop ──────────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n\n=== JK/Daly BMS BLE Reader (D2 protocol, verified offsets) ===");
    Serial.printf("Target: %s\n\n", BMS_ADDRESS);

    memset(&bms, 0, sizeof(bms));
    BLEDevice::init("ESP32_BMS");
}

void loop() {
    if (!connected) {
        if (!ble_connect()) {
            Serial.println("Retrying in 5s...");
            delay(5000);
            return;
        }
    }

    send_request();

    uint32_t deadline = millis() + RESPONSE_WAIT_MS;
    notify_ready = false;
    while (millis() < deadline) {
        if (notify_ready) {
            notify_ready = false;
            process_rx_buffer();
        }
        delay(10);
    }

    if (bms.valid)
        print_bms();
    else
        Serial.println("[INFO] Waiting for data...");

    delay(POLL_INTERVAL_MS);
}
