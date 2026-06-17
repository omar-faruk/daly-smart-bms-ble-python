"""
JK/Daly BMS BLE Reader  —  P81 Modbus RTU protocol
====================================================
Protocol sources:
  1. btsnoop_wireshark.pcap  — Smart BMS Pro Android BLE capture
  2. LightBlue log           — confirmed GATT UUIDs
  3. daly_bms_ble.cpp        — ESPHome open-source component

Device tested:  JX12100-251210360  (70:C1:45:30:11:52)
Firmware:       82_250902_K00TH2.1

━━━ BLE transport ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Service  0000fff0-0000-1000-8000-00805f9b34fb
  RX char  0000fff1-...  Notify           BMS → app
  TX char  0000fff2-...  WriteWithoutResp app → BMS

━━━ Request frame (8 bytes) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [0]    0x81         Modbus slave address
  [1]    0x03         Read Holding Registers
  [2-3]  uint16 BE    Register start address
  [4-5]  uint16 BE    Register count  (1 reg = 2 bytes)
  [6-7]  uint16 LE    CRC-16/Modbus

━━━ Response frame (fff1 notification) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [0]    0x51         Slave echo
  [1]    0x03         Function echo
  [2]    uint8        Byte count N = register_count × 2
  [3..N+2]            Register data (big-endian uint16 per register)
  [N+3..N+4]          CRC-16/Modbus (little-endian)

━━━ Register map ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  0x0000  65 regs  CELLS     cell voltages, temps, pack totals
  0x0041  62 regs  STATUS    MOS state, balance, energy, temps
  0x00A4  10 regs  ALARMS    fault bitmask
  0x0178  74 regs  VERSION   firmware / serial strings
  0x00CF   1 reg   BALANCER  balancer on/off

━━━ CELLS layout (verified from real captured frame) ━━━━━━━━━━━━━━━
  reg 0x00..0x2F  cell voltages 1..48  uint16  mV  (÷1000 = V)
  reg 0x30..0x37  temperatures 1..8   uint16  raw−40 °C (0x00FF = absent)
  reg 0x38        total pack voltage   uint16  ×0.1 V
  reg 0x39        nominal capacity     uint16  mAh
  reg 0x3A        current magnitude    uint16  ×0.01 A  (unsigned)
                  sign from STATUS reg 0x48: 1=charging(+), 2=discharging(-)
  reg 0x3B        SOC                  uint16  ÷2 = %
  reg 0x3C        cell count           uint16
  reg 0x3D        temperature sensor count  uint16
  reg 0x3E        max cell voltage     uint16  mV
  reg 0x3F        max cell index       uint16  0-based
  reg 0x40        min cell voltage     uint16  mV

━━━ STATUS layout (reg−0x41 offset) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  reg 0x43  max battery temperature  raw−40 °C
  reg 0x45  min battery temperature  raw−40 °C
  reg 0x48  charge/discharge status  0=idle 1=chg(+) 2=dis(-)
  reg 0x4B  remaining capacity       ×0.1 Ah
  reg 0x4C  charging cycles
  reg 0x4D  balancing state          0=off 1=passive 2=active
  reg 0x4E  balance current          (raw−30000)×0.001 A
  reg 0x52  charging MOSFET          0=off 1=on
  reg 0x53  discharging MOSFET       0=off 1=on
  reg 0x54  pre-charge MOSFET        0=off 1=on
  reg 0x59  energy counter           Wh
  reg 0x5A  MOSFET temperature       raw−40 °C
  reg 0x5B  board temperature        raw−40 °C

Usage:
    pip install bleak
    python jk_bms_ble.py                          # auto-scan
    python jk_bms_ble.py 70:C1:45:30:11:52       # direct address
    python jk_bms_ble.py --decode cells  5103820d05...
    LOG_LEVEL=DEBUG python jk_bms_ble.py <addr>   # verbose
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional, List

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger("jk_bms")

# ── GATT UUIDs ────────────────────────────────────────────────────────────────
SERVICE_UUID  = "0000fff0-0000-1000-8000-00805f9b34fb"
CHAR_RX_UUID  = "0000fff1-0000-1000-8000-00805f9b34fb"
CHAR_TX_UUID  = "0000fff2-0000-1000-8000-00805f9b34fb"

SLAVE_REQ  = 0x81
SLAVE_RESP = 0x51

# Register addresses and counts
# IMPORTANT: CELLS uses count=65 (not 64). The BMS only responds to count=65
# for addr=0x0000, as confirmed by pcap capture (request: 8103000000419a3a).
REG_CELLS    = (0x0000, 65)   # 65 regs = 130 bytes; count=64 gets no response
REG_STATUS   = (0x0041, 62)
REG_ALARMS   = (0x00A4, 10)
REG_VERSION  = (0x0178, 74)
REG_BALANCER = (0x00CF,  1)

POLL_CYCLE = [REG_CELLS, REG_STATUS, REG_VERSION]

BMS_NAME_PREFIXES = ("JX", "JK", "BMS")

ERRORS = [
    "","","","","","","","",
    "","","","","","","","",
    "Charging MOS over-temperature warning",
    "Discharging MOS over-temperature warning",
    "Charging MOS temperature sensor failure",
    "Discharging MOS temperature sensor failure",
    "Charging MOS adhesion failure",
    "Discharging MOS adhesion failure",
    "Charging MOS circuit fault",
    "Discharging MOS circuit fault",
    "AFE acquisition chip failure",
    "Single unit collection is offline",
    "Single temperature sensor failure",
    "EEPROM storage failure",
    "RTC clock failure",
    "Precharge failed",
    "Vehicle communication failed",
    "Internal network communication module failure",
    "Warning: Charging current too high",
    "Critical: Charging current too high",
    "Warning: Discharging current too low",
    "Critical: Discharging current too low",
    "Warning: SOC too high",
    "Critical: SOC too high",
    "Warning: SOC too low",
    "Critical: SOC too low",
    "Warning: Voltage difference too high",
    "Critical: Voltage difference too high",
    "Warning: Temperature difference too high",
    "Critical: Temperature difference too high",
    "","","","",
    "Warning: Cell voltage too high",
    "Critical: Cell voltage too high",
    "Warning: Cell voltage too low",
    "Critical: Cell voltage too low",
    "Warning: Total voltage too high",
    "Critical: Total voltage too high",
    "Warning: Total voltage too low",
    "Critical: Total voltage too low",
    "Warning: Charging temperature too high",
    "Critical: Charging temperature too high",
    "Warning: Charging temperature too low",
    "Critical: Charging temperature too low",
    "Warning: Discharging temperature too high",
    "Critical: Discharging temperature too high",
    "Warning: Discharging temperature too low",
    "Critical: Discharging temperature too low",
]


# ── Modbus RTU ────────────────────────────────────────────────────────────────

def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def build_request(addr: int, count: int) -> bytes:
    hdr = bytes([SLAVE_REQ, 0x03]) + struct.pack(">HH", addr, count)
    return hdr + struct.pack("<H", _crc16(hdr))


def parse_response(raw: bytes) -> tuple[Optional[bytes], Optional[str]]:
    if len(raw) < 5:
        return None, f"too short ({len(raw)} B)"
    if raw[0] != SLAVE_RESP:
        return None, f"bad slave 0x{raw[0]:02X}"
    if raw[1] == 0x83:
        return None, f"Modbus exception 0x{raw[2]:02X}"
    if raw[1] != 0x03:
        return None, f"unexpected function 0x{raw[1]:02X}"
    n = raw[2]
    if len(raw) < 3 + n + 2:
        return None, f"truncated (have {len(raw)}, need {3+n+2})"
    stored   = struct.unpack_from("<H", raw, 3 + n)[0]
    computed = _crc16(raw[:3 + n])
    if stored != computed:
        return None, f"CRC 0x{stored:04X} ≠ 0x{computed:04X}"
    return raw[3:3 + n], None


def _r(payload: bytes, reg: int, base: int = 0) -> int:
    """Read register *reg* as unsigned 16-bit BE from the data payload."""
    return struct.unpack_from(">H", payload, (reg - base) * 2)[0]


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class BMSData:
    # ── CELLS ─────────────────────────────────────────────────────────────────
    cell_voltages_v:     List[float]    = field(default_factory=list)
    temperatures_c:      List[float]    = field(default_factory=list)
    total_voltage_v:     float          = 0.0
    current_a:           float          = 0.0   # +ve = charging, -ve = discharging
    nominal_capacity_mah: int           = 0
    soc_pct:             float          = 0.0
    max_cell_v:          float          = 0.0
    min_cell_v:          float          = 0.0
    max_cell_index:      int            = 0     # 0-based
    min_cell_index:      int            = 0     # 0-based
    cell_count:          int            = 0
    temp_sensor_count:   int            = 0

    # ── STATUS ────────────────────────────────────────────────────────────────
    battery_status:        str            = ""
    capacity_remaining_ah: float          = 0.0
    charging_cycles:       int            = 0
    balancing:             bool           = False
    balancing_state:       int            = 0
    balance_current_a:     float          = 0.0
    charging_mos:          bool           = False
    discharging_mos:       bool           = False
    precharging_mos:       bool           = False
    energy_wh:             int            = 0
    mosfet_temp_c:         Optional[float] = None
    board_temp_c:          Optional[float] = None
    max_battery_temp_c:    Optional[float] = None
    min_battery_temp_c:    Optional[float] = None

    # ── VERSION ───────────────────────────────────────────────────────────────
    firmware_version: str = ""
    serial_number:    str = ""
    manufacture_date: str = ""

    # ── Internal ──────────────────────────────────────────────────────────────
    _cells_received:   bool  = field(default=False, repr=False)
    _status_received:  bool  = field(default=False, repr=False)
    _current_mag:      float = field(default=0.0,   repr=False)  # unsigned magnitude

    @property
    def power_w(self) -> float:
        return self.total_voltage_v * self.current_a

    @property
    def delta_cell_mv(self) -> float:
        if not self.cell_voltages_v:
            return 0.0
        return (max(self.cell_voltages_v) - min(self.cell_voltages_v)) * 1000

    def fully_populated(self) -> bool:
        return self._cells_received and self._status_received

    def __str__(self) -> str:
        lines = ["=" * 66]

        if self.cell_voltages_v:
            cells = "  ".join(
                f"C{i+1}:{v:.3f}V" for i, v in enumerate(self.cell_voltages_v)
            )
            lines.append(f"  {cells}")
            lines.append(
                f"  Pack:   {self.total_voltage_v:.3f} V"
                f"    I: {self.current_a:+.2f} A  ({self.battery_status or '?'})"
                f"    P: {self.power_w:+.1f} W"
            )
            lines.append(
                f"  SOC:    {self.soc_pct:.1f}%"
                f"    Remain: {self.capacity_remaining_ah:.1f} Ah"
                f"    Cap: {self.nominal_capacity_mah/1000:.1f} Ah"
                f"    Cycles: {self.charging_cycles}"
            )
            lines.append(
                f"  Max: C{self.max_cell_index+1} {self.max_cell_v:.3f}V"
                f"    Min: C{self.min_cell_index+1} {self.min_cell_v:.3f}V"
                f"    Δ: {self.delta_cell_mv:.0f} mV"
            )
        else:
            lines.append("  Cells: (not received yet)")

        if self._status_received:
            lines.append(
                f"  MOS:  CHG={'ON ' if self.charging_mos else 'off'}"
                f"  DIS={'ON ' if self.discharging_mos else 'off'}"
                f"  PRE={'ON ' if self.precharging_mos else 'off'}"
                f"    Bal: {'ACTIVE('+str(self.balancing_state)+')' if self.balancing else 'idle'}"
                f"  {self.balance_current_a:+.3f} A"
            )

        temps = []
        if self.mosfet_temp_c is not None:
            temps.append(f"MOS:{self.mosfet_temp_c:.0f}°C")
        if self.board_temp_c is not None and -40 < self.board_temp_c < 150:
            temps.append(f"Board:{self.board_temp_c:.0f}°C")
        if self.max_battery_temp_c is not None and -40 < self.max_battery_temp_c < 150:
            temps.append(f"BatMax:{self.max_battery_temp_c:.0f}°C")
        for i, t in enumerate(self.temperatures_c):
            if -40 < t < 100:
                temps.append(f"T{i+1}:{t:.0f}°C")
        if temps:
            lines.append(f"  Temps:  {' '.join(temps)}")

        if self.energy_wh:
            lines.append(f"  Energy: {self.energy_wh} Wh")

        if self.firmware_version:
            lines.append(f"  FW: {self.firmware_version}")
            lines.append(f"  SN: {self.serial_number}")

        lines.append("=" * 66)
        return "\n".join(lines)


# ── Current sign helper ───────────────────────────────────────────────────────

def _apply_current_sign(bms: BMSData) -> None:
    """
    Apply the correct sign to current_a from the unsigned magnitude in CELLS.

    CELLS reg 0x3A gives the magnitude × 0.01 A.
    STATUS reg 0x48 gives the direction: 0=idle, 1=charging(+), 2=discharging(-).
    This is called after either frame is decoded so both orderings work.
    """
    if bms._current_mag == 0.0:
        return
    status = bms.battery_status
    if status == "Charging":
        bms.current_a = +bms._current_mag
    elif status == "Discharging":
        bms.current_a = -bms._current_mag
    else:
        # Idle or unknown — keep magnitude, no sign
        bms.current_a = bms._current_mag


# ── Register decoders ─────────────────────────────────────────────────────────

def decode_cells(payload: bytes, bms: BMSData) -> None:
    """
    Decode the 65-register (130-byte) CELLS response.
    Register layout verified byte-by-byte from a real captured pcap frame.

      reg 0x00..0x2F  cell voltages 1..48   uint16  mV  (÷1000 = V)
      reg 0x30..0x37  temperatures 1..8     uint16  raw−40 °C (0x00FF = absent)
      reg 0x38        total pack voltage     uint16  ×0.1 V
      reg 0x39        nominal capacity       uint16  mAh
      reg 0x3A        current magnitude      uint16  ×0.01 A  (unsigned)
      reg 0x3B        SOC                    uint16  ÷2 = %
      reg 0x3C        cell count             uint16
      reg 0x3D        temperature sensor count uint16
      reg 0x3E        max cell voltage       uint16  mV
      reg 0x3F        max cell index         uint16  0-based
      reg 0x40        min cell voltage       uint16  mV
    """
    if len(payload) < 130:
        logger.debug("CELLS payload too short: %d bytes (need 130)", len(payload))
        return

    cell_count = min(_r(payload, 0x3C), 48)
    temp_count = min(_r(payload, 0x3D),  8)
    bms.cell_count        = cell_count
    bms.temp_sensor_count = temp_count

    # Cell voltages (mV → V)
    bms.cell_voltages_v = [_r(payload, i) * 0.001 for i in range(cell_count)]

    # Temperatures (raw − 40 = °C); skip 0x00FF sentinel (= not fitted)
    bms.temperatures_c = [
        _r(payload, 0x30 + i) - 40
        for i in range(temp_count)
        if _r(payload, 0x30 + i) != 0x00FF
    ]

    bms.total_voltage_v      = _r(payload, 0x38) * 0.1
    bms.nominal_capacity_mah = _r(payload, 0x39)
    bms._current_mag         = _r(payload, 0x3A) * 0.01
    bms.soc_pct              = _r(payload, 0x3B) / 2.0
    bms.max_cell_v           = _r(payload, 0x3E) * 0.001
    bms.max_cell_index       = _r(payload, 0x3F)
    bms.min_cell_v           = _r(payload, 0x40) * 0.001

    # Derive min index from cell array
    cells = bms.cell_voltages_v
    if cells:
        try:
            bms.min_cell_index = cells.index(min(cells))
        except ValueError:
            bms.min_cell_index = 0

    # Apply sign if STATUS already decoded
    _apply_current_sign(bms)

    bms._cells_received = True

    logger.info(
        "[CELLS] %.3fV  %+.2fA  SOC=%.1f%%  cap=%dmAh  cells=%d  "
        "max=%.3fV(C%d)  min=%.3fV(C%d)  Δ=%.0fmV",
        bms.total_voltage_v, bms.current_a, bms.soc_pct,
        bms.nominal_capacity_mah, cell_count,
        bms.max_cell_v, bms.max_cell_index + 1,
        bms.min_cell_v, bms.min_cell_index + 1,
        bms.delta_cell_mv,
    )


def decode_status(payload: bytes, bms: BMSData) -> None:
    """
    Decode the 62-register (124-byte) STATUS response.
    Registers addressed as (reg − 0x41) × 2 from payload start.
    """
    if len(payload) < 124:
        logger.debug("STATUS payload too short: %d bytes (need 124)", len(payload))
        return

    def r(reg: int) -> int:
        return _r(payload, reg, base=0x41)

    code = r(0x48)
    bms.battery_status        = {0: "Idle", 1: "Charging", 2: "Discharging"}.get(code, f"Unknown({code})")
    bms.capacity_remaining_ah = r(0x4B) * 0.1
    bms.charging_cycles       = r(0x4C)
    bms.balancing_state       = r(0x4D)
    bms.balancing             = bms.balancing_state != 0
    bms.balance_current_a     = (r(0x4E) - 30000) * 0.001
    bms.charging_mos          = r(0x52) == 1
    bms.discharging_mos       = r(0x53) == 1
    bms.precharging_mos       = r(0x54) == 1
    bms.energy_wh             = r(0x59)
    bms.mosfet_temp_c         = r(0x5A) - 40
    brd                       = r(0x5B) - 40
    bms.board_temp_c          = brd if -40 <= brd <= 150 else None
    bms.max_battery_temp_c    = r(0x43) - 40
    bms.min_battery_temp_c    = r(0x45) - 40

    bms._status_received = True

    # Fix current sign now that we know the direction
    _apply_current_sign(bms)

    logger.info(
        "[STATUS] %s  remain=%.1fAh  cycles=%d  bal=%s  "
        "chg=%s  dis=%s  mos_temp=%d°C",
        bms.battery_status, bms.capacity_remaining_ah, bms.charging_cycles,
        "on" if bms.balancing else "off",
        "ON" if bms.charging_mos else "off",
        "ON" if bms.discharging_mos else "off",
        bms.mosfet_temp_c or 0,
    )


def decode_version(payload: bytes, bms: BMSData) -> None:
    """Decode null-separated ASCII strings from the VERSION response."""
    parts = [
        p.decode("ascii", errors="replace").strip()
        for p in payload.split(b"\x00")
        if p.strip(b"\x00 \xff")
    ]
    if parts:           bms.firmware_version = parts[0]
    if len(parts) > 1:  bms.serial_number    = parts[1]
    if len(parts) > 2:  bms.manufacture_date = parts[2]
    logger.info("[VERSION] FW=%s  SN=%s", bms.firmware_version, bms.serial_number)


def decode_alarms(payload: bytes, bms: BMSData) -> None:
    """Log any active alarm bits from the ALARMS response."""
    if len(payload) < 10:
        return
    bitmask = 0
    for i in range(min(len(payload) // 2, 8)):
        bitmask |= _r(payload, i) << (i * 16)
    active = [ERRORS[i] for i in range(min(len(ERRORS), 64)) if (bitmask >> i) & 1 and ERRORS[i]]
    if active:
        logger.warning("[ALARMS] %s", " | ".join(active))
    else:
        logger.debug("[ALARMS] no active alarms")


def dispatch(reg_addr: int, payload: bytes, bms: BMSData) -> None:
    if   reg_addr == 0x0000: decode_cells(payload, bms)
    elif reg_addr == 0x0041: decode_status(payload, bms)
    elif reg_addr == 0x0178: decode_version(payload, bms)
    elif reg_addr == 0x00A4: decode_alarms(payload, bms)
    else:
        logger.debug("No decoder for reg 0x%04X (%d bytes)", reg_addr, len(payload))


# ── BLE client ────────────────────────────────────────────────────────────────

class JKBMS:
    """
    Async BLE client for JK/Daly BMS (P81 Modbus RTU protocol).

    Poll-based — the app requests data by writing to fff2; BMS replies on fff1.
    No authentication required.
    """

    def __init__(self, address: str):
        self.address       = address
        self.data          = BMSData()
        self._client: Optional[BleakClient]             = None
        self._rx:     Optional[BleakGATTCharacteristic] = None
        self._tx:     Optional[BleakGATTCharacteristic] = None
        self._buf          = bytearray()
        self._pending_addr = 0
        self._cells_ready  = asyncio.Event()   # set when CELLS first decoded
        self._full_ready   = asyncio.Event()   # set when CELLS + STATUS decoded

    # ── Notification handler ──────────────────────────────────────────────────

    def _on_notify(self, _: BleakGATTCharacteristic, chunk: bytearray) -> None:
        self._buf.extend(chunk)
        logger.debug("← %s  (buf %dB)", chunk.hex(), len(self._buf))

        while len(self._buf) >= 5:
            if self._buf[0] != SLAVE_RESP or self._buf[1] != 0x03:
                logger.debug("Sync lost, dropping 0x%02X", self._buf[0])
                del self._buf[0]
                continue

            n    = self._buf[2]
            need = 3 + n + 2
            if len(self._buf) < need:
                break

            frame = bytes(self._buf[:need])
            del self._buf[:need]

            payload, err = parse_response(frame)
            if err:
                logger.warning("Bad frame: %s  raw=%s", err, frame.hex())
                continue

            dispatch(self._pending_addr, payload, self.data)

            if self.data._cells_received:
                self._cells_ready.set()
            if self.data.fully_populated():
                self._full_ready.set()

    # ── GATT discovery ────────────────────────────────────────────────────────

    async def _find_chars(self) -> None:
        assert self._client
        for svc in self._client.services:
            logger.debug("SVC %s", svc.uuid)
            for ch in svc.characteristics:
                logger.debug("  CH %s  0x%04X  %s", ch.uuid, ch.handle, ch.properties)
                u = ch.uuid.lower()
                if u == CHAR_RX_UUID: self._rx = ch
                if u == CHAR_TX_UUID: self._tx = ch

        # Fallback: match by property within fff0 service
        if self._rx is None or self._tx is None:
            for svc in self._client.services:
                if SERVICE_UUID not in svc.uuid.lower():
                    continue
                for ch in svc.characteristics:
                    if "notify" in ch.properties and self._rx is None:
                        self._rx = ch
                        logger.info("Fallback RX: %s", ch.uuid)
                    if (("write" in ch.properties or
                         "write-without-response" in ch.properties)
                            and self._tx is None):
                        self._tx = ch
                        logger.info("Fallback TX: %s", ch.uuid)

        if self._rx is None:
            raise RuntimeError("RX char (fff1) not found. Run LOG_LEVEL=DEBUG to inspect.")
        if self._tx is None:
            raise RuntimeError("TX char (fff2) not found.")

        logger.info("RX: %s  0x%04X", self._rx.uuid, self._rx.handle)
        logger.info("TX: %s  0x%04X", self._tx.uuid, self._tx.handle)

    # ── Modbus send ───────────────────────────────────────────────────────────

    async def _request(self, addr: int, count: int) -> None:
        """Send one Modbus request and pause 350 ms for the BMS to respond."""
        assert self._client and self._tx
        self._pending_addr = addr
        frame = build_request(addr, count)
        logger.debug("→ reg=0x%04X count=%d  %s", addr, count, frame.hex())
        use_response = "write" in self._tx.properties
        await self._client.write_gatt_char(self._tx, frame, response=use_response)
        await asyncio.sleep(0.35)   # BMS needs ~200 ms; 350 ms gives headroom

    # ── Public API ────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        logger.info("Connecting to %s …", self.address)
        self._client = BleakClient(self.address, timeout=15.0)
        await self._client.connect()
        if not self._client.is_connected:
            raise RuntimeError("Connection failed")
        logger.info("Connected.")
        await self._find_chars()
        await self._client.start_notify(self._rx, self._on_notify)
        logger.info("Subscribed to fff1 notifications. Allowing stack to settle...")
        
        # --- FIX 1: Allow BLE descriptor write to completely clear ---
        await asyncio.sleep(1.0)

    async def disconnect(self) -> None:
        if self._client and self._client.is_connected:
            if self._rx:
                try: await self._client.stop_notify(self._rx)
                except Exception: pass
            await self._client.disconnect()
        logger.info("Disconnected.")

    async def poll_once(self) -> BMSData:
        """Request every register block; each waits 350 ms for the BMS response."""
        for addr, count in POLL_CYCLE:
            await self._request(addr, count)
        return self.data

    async def wait_for_data(self, timeout: float = 20.0) -> BMSData:
        """Poll periodically until both CELLS and STATUS are received or timeout hits."""
        start_time = asyncio.get_event_loop().time()
        
        # --- FIX 2: Dynamic loop that retries if frames get dropped ---
        while not self.data.fully_populated():
            if asyncio.get_event_loop().time() - start_time > timeout:
                if self.data._cells_received:
                    logger.warning("STATUS not received — showing cells-only data")
                    break
                raise asyncio.TimeoutError("Timeout waiting for initial BMS data blocks")
            
            # Fire a poll cycle
            asyncio.ensure_future(self.poll_once())
            
            # Wait 2.5 seconds for the response sequence to clear out before evaluating/retrying
            await asyncio.sleep(2.5)
            
        return self.data

    async def stream(self, interval: float = 2.0):
        """Async generator — poll every *interval* seconds and yield BMSData."""
        while True:
            self._full_ready.clear()
            self._cells_ready.clear()
            await self.poll_once()
            try:
                await asyncio.wait_for(self._full_ready.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                if self._cells_ready.is_set():
                    logger.warning("STATUS timeout in stream cycle")
                else:
                    logger.warning("CELLS timeout in stream cycle")
            yield self.data
            await asyncio.sleep(interval)


# ── Scanner ───────────────────────────────────────────────────────────────────

async def find_bms(timeout: float = 10.0) -> Optional[str]:
    logger.info("Scanning %.0fs for JK/JX BMS …", timeout)
    devices = await BleakScanner.discover(timeout=timeout)
    for d in devices:
        name = (d.name or "").upper()
        if any(name.startswith(p) for p in BMS_NAME_PREFIXES):
            logger.info("Found: %s  [%s]", d.name, d.address)
            return d.address
        if hasattr(d, "metadata"):
            uuids = [u.lower() for u in d.metadata.get("uuids", [])]
            if SERVICE_UUID in uuids:
                logger.info("Found by UUID: %s  [%s]", d.name, d.address)
                return d.address
    logger.warning("No BMS found.")
    return None


# ── Offline decoder ───────────────────────────────────────────────────────────

def decode_offline(reg_name: str, hex_frame: str) -> BMSData:
    """
    Decode a captured hex frame without BLE.

    reg_name  : "cells", "status", "version", or "alarms"
    hex_frame : full Modbus response as hex (including 0x51 header + CRC)

    Example:
        bms = decode_offline("cells", "5103820d05...")
        print(bms)
    """
    addr_map = {
        "cells":   0x0000,
        "status":  0x0041,
        "alarms":  0x00A4,
        "version": 0x0178,
    }
    reg_addr = addr_map.get(reg_name.lower())
    if reg_addr is None:
        raise ValueError(f"Unknown register '{reg_name}'. Use: cells, status, alarms, version")
    raw = bytes.fromhex(hex_frame.replace(" ", "").replace("\n", ""))
    payload, err = parse_response(raw)
    if err:
        raise ValueError(f"Frame error: {err}")
    bms = BMSData()
    dispatch(reg_addr, payload, bms)
    return bms


# ── CLI ───────────────────────────────────────────────────────────────────────

async def main() -> None:
    args = sys.argv[1:]

    if args and args[0] == "--decode":
        if len(args) < 3:
            print("Usage: python jk_bms_ble.py --decode <cells|status|version|alarms> <hex>")
            return
        bms = decode_offline(args[1], args[2])
        print(bms)
        return

    cells_req  = build_request(*REG_CELLS)
    status_req = build_request(*REG_STATUS)

    address = args[0] if args else await find_bms()
    if not address:
        print(
            "No BMS found.\n\n"
            "Connect directly:\n"
            "  python jk_bms_ble.py 70:C1:45:30:11:52\n\n"
            "Debug all GATT services:\n"
            "  LOG_LEVEL=DEBUG python jk_bms_ble.py 70:C1:45:30:11:52\n\n"
            "Manual test via LightBlue:\n"
            "  1. Enable notifications on fff1\n"
            "  2. Write to fff2 (WriteWithoutResponse):\n"
            f"     CELLS  request: {cells_req.hex()}  (expect ~135-byte response)\n"
            f"     STATUS request: {status_req.hex()}  (expect ~129-byte response)"
        )
        return

    bms_client = JKBMS(address)
    try:
        await bms_client.connect()
        print("Polling BMS …")
        try:
            data = await bms_client.wait_for_data(timeout=20.0)
        except asyncio.TimeoutError:
            print(
                "\nTimeout — BMS connected but CELLS not responding.\n\n"
                "Most likely cause: another app is connected (Smart BMS Pro, Daly BMS).\n"
                "Close it, then retry.\n\n"
                "Manual test via LightBlue — write to fff2:\n"
                f"  {cells_req.hex()}\n"
                "  Expect a ~135-byte notification on fff1 starting with 5103 82."
            )
            return

        print(data)
        print("Streaming (Ctrl-C to stop) …\n")
        async for snapshot in bms_client.stream(interval=2.0):
            print(snapshot)

    except KeyboardInterrupt:
        pass
    finally:
        await bms_client.disconnect()


if __name__ == "__main__":
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.getLogger().setLevel(getattr(logging, level, logging.INFO))
    asyncio.run(main())
