#!/usr/bin/env python3
"""
Daly BMS reader over BLE using Bleak
Reads telemetry via Modbus protocol (Daly v2)
References:
  - https://github.com/roccotsi2/esp32-smart-bms-simulation
  - https://github.com/tomatensaus/python-daly-bms
"""

import asyncio
import struct
from bleak import BleakClient, BleakScanner
from datetime import datetime

# ─────────────────────────────────────────────────────────────────
# BMS Configuration
# ─────────────────────────────────────────────────────────────────

BMS_ADDRESS = "70:C1:45:30:11:52"  # Your BMS address
UUID_RX = "0000fff1-0000-1000-8000-00805f9b34fb"  # Notify (read)
UUID_TX = "0000fff2-0000-1000-8000-00805f9b34fb"  # Write
TIMEOUT = 8.0  # seconds

# Main data read command (Modbus: read 62 registers starting at 0x0000)
# Slave ID 0xD2, Function 0x03, Start 0x0000, Count 0x003E, CRC 0xD7B9
DALY_CMD_MAIN = bytes.fromhex("D2 03 00 00 00 3E D7 B9")

# ─────────────────────────────────────────────────────────────────
# Modbus CRC-16
# ─────────────────────────────────────────────────────────────────

def modbus_crc16(data: bytes) -> int:
    """Calculate Modbus CRC-16-CCITT (big-endian)"""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc

# ─────────────────────────────────────────────────────────────────
# BMS Data Parser
# ─────────────────────────────────────────────────────────────────

class DalyBmsData:
    """Parse Daly BMS Modbus response"""
    
    def __init__(self, raw_data: bytes):
        """
        Parse raw BMS response buffer
        Format: [slave_id][func_code][byte_count][data...][crc_lo][crc_hi]
        """
        self.raw = raw_data
        self.is_valid = len(raw_data) >= 5 and raw_data.endswith(b'w')
        
        if self.is_valid:
            # Strip header and trailer
            self.buffer = bytearray(raw_data[3:-1])  # Skip [DD][A5] and trailing 'w'
        else:
            self.buffer = bytearray()
    
    def _read_u16(self, offset: int) -> int:
        """Read big-endian uint16"""
        if offset + 1 < len(self.buffer):
            return struct.unpack('>H', self.buffer[offset:offset+2])[0]
        return 0
    
    def _read_i16(self, offset: int) -> int:
        """Read big-endian int16 (signed)"""
        if offset + 1 < len(self.buffer):
            return struct.unpack('>h', self.buffer[offset:offset+2])[0]
        return 0
    
    def _read_u32(self, offset: int) -> int:
        """Read big-endian uint32"""
        if offset + 3 < len(self.buffer):
            return struct.unpack('>I', self.buffer[offset:offset+4])[0]
        return 0
    
    # ─── Main metrics ───
    @property
    def pack_voltage(self) -> float:
        """Pack voltage in V (byte 80-81, unit 0.1V)"""
        return self._read_u16(80) / 10
    
    @property
    def pack_current(self) -> float:
        """Pack current in A (byte 82-83, offset 30000, unit 0.1A)"""
        raw = self._read_u16(82)
        return (raw - 30000) / 100.0
    
    @property
    def soc(self) -> float:
        """State of charge in % (byte 84-85, unit 0.1%)"""
        return self._read_u16(84) / 10
    
    @property
    def capacity_remaining(self) -> float:
        """Remaining capacity in Ah (byte 96-97, unit 0.1Ah)"""
        return self._read_u16(96) / 10
    
    @property
    def cycle_count(self) -> int:
        """Number of charge cycles (byte 102-103)"""
        return self._read_u16(102)
    
    # ─── Temperatures ───
    @property
    def num_temps(self) -> int:
        """Number of temperature sensors (byte 100-101)"""
        return self._read_u16(100)
    
    @property
    def temperatures(self) -> list:
        """Temperature readings in °C (offset -40)"""
        temps = []
        for i in range(min(self.num_temps, 16)):  # Max 16 sensors
            raw = self._read_u16(64 + i * 2)
            if raw > 0:
                temps.append(raw - 40)
        return temps
    
    # ─── Switch status ───
    @property
    def mos_byte(self) -> int:
        """MOS status byte (byte 20): 1=charge, 2=discharge, 3=both"""
        return self.buffer[20] if len(self.buffer) > 20 else 0
    
    @property
    def charge_enabled(self) -> bool:
        """Charge MOSFET enabled"""
        return self.mos_byte in (1, 3)
    
    @property
    def discharge_enabled(self) -> bool:
        """Discharge MOSFET enabled"""
        return self.mos_byte in (2, 3)
    
    # ─── Alarms ───
    @property
    def problem_code(self) -> int:
        """8-byte alarm bitmask (byte 116-123)"""
        return self._read_u32(116) << 32 | self._read_u32(120)
    
    @property
    def has_alarm(self) -> bool:
        """Any alarm active"""
        return self.problem_code != 0
    
    def __str__(self) -> str:
        """Pretty print BMS status"""
        if not self.is_valid:
            return "[Invalid data]"
        
        lines = [
            "╔════════════════════════════════════════╗",
            "║         DALY BMS STATUS                ║",
            "╠════════════════════════════════════════╣",
            f"║  Voltage:        {self.pack_voltage:7.2f} V",
            f"║  Current:        {self.pack_current:+7.2f} A  ({'CHG' if self.pack_current > 0 else 'DSG' if self.pack_current < 0 else 'IDLE'})",
            f"║  SOC:            {self.soc:7.1f} %",
            f"║  Remaining:      {self.capacity_remaining:7.1f} Ah",
            f"║  Cycles:        {self.cycle_count:7d}",
            "╠════════════════════════════════════════╣",
        ]
        
        # Temperatures
        if self.temperatures:
            for i, temp in enumerate(self.temperatures, 1):
                lines.append(f"║  Temp {i}:         {temp:7.1f} °C")
        
        # Switches
        lines.append("╠════════════════════════════════════════╣")
        lines.append(f"║  Charge FET:     {'ON ✓' if self.charge_enabled else 'OFF'}")
        lines.append(f"║  Discharge FET:  {'ON ✓' if self.discharge_enabled else 'OFF'}")
        
        # Alarms
        if self.has_alarm:
            lines.append("║  🚨 ALARM ACTIVE")
            lines.append(f"║  Code:           0x{self.problem_code:016X}")
        else:
            lines.append("║  Status:         OK ✓")
        
        lines.append("╚════════════════════════════════════════╝")
        return "\n".join(lines)

# ─────────────────────────────────────────────────────────────────
# BLE Communication
# ─────────────────────────────────────────────────────────────────

class DalyBmsReader:
    """Daly BMS BLE reader"""
    
    def __init__(self, address: str = BMS_ADDRESS):
        self.address = address
        self.client = None
        self.buffer = bytearray()
        self.response_event = None
    
    def _notification_handler(self, sender, data):
        """Handle incoming BLE notifications"""
        self.buffer.extend(data)
        # print(f"[RX] +{len(data)}B: {data.hex().upper()}")
        
        # Response ends with 'w' (0x77)
        if self.buffer.endswith(b'w'):
            if self.response_event:
                self.response_event.set()
    
    async def connect(self):
        """Connect to BMS and start notifications"""
        print(f"Scanning for {self.address}...")
        device = await BleakScanner.find_device_by_address(self.address, timeout=10.0)
        
        if not device:
            raise RuntimeError(f"Could not find device {self.address}")
        
        print(f"✓ Found: {device.name}")
        self.client = BleakClient(device)
        await self.client.connect()
        print(f"✓ Connected (MTU={self.client.mtu_size})")
        
        # Start notifications
        await self.client.start_notify(UUID_RX, self._notification_handler)
        print(f"✓ Subscribed to {UUID_RX[-8:]}")
        
        self.response_event = asyncio.Event()
    
    async def disconnect(self):
        """Disconnect from BMS"""
        if self.client:
            await self.client.stop_notify(UUID_RX)
            await self.client.disconnect()
            print("✓ Disconnected")
    
    async def read(self, timeout: float = TIMEOUT) -> DalyBmsData:
        """
        Read BMS data
        
        Returns:
            DalyBmsData: Parsed BMS response
        """
        # Clear buffer and event
        self.buffer.clear()
        if self.response_event:
            self.response_event.clear()
        
        # Send command
        print(f"→ Sending command: {DALY_CMD_MAIN.hex().upper()}")
        await self.client.write_gatt_char(UUID_TX, DALY_CMD_MAIN, response=False)
        
        # Wait for response
        try:
            await asyncio.wait_for(self.response_event.wait(), timeout=timeout)
            response = bytes(self.buffer)
            print(f"✓ Received {len(response)}B")
            return DalyBmsData(response)
        except asyncio.TimeoutError:
            print(f"✗ Timeout waiting for response ({timeout}s)")
            return DalyBmsData(b"")

# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────

async def main():
    reader = DalyBmsReader(BMS_ADDRESS)
    
    try:
        await reader.connect()
        await asyncio.sleep(1.0)
        
        # Read once
        print("\n" + "="*42)
        data = await reader.read()
        print(data)
        print("="*42)
        
        # Optional: continuous polling
        print("\nContinuous polling (Ctrl+C to stop)...\n")
        try:
            while True:
                await asyncio.sleep(2.0)
                data = await reader.read()
                print(data)
        except KeyboardInterrupt:
            print("\nStopped.")
    
    finally:
        await reader.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
