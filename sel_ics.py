from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusIOException
from datetime import datetime

class SEL787Scanner:
    def __init__(self, ip, port=502, test_mode=False):
        self.ip = ip
        self.port = port
        self.test_mode = test_mode
        self.report = []
        self.client = ModbusTcpClient(self.ip, port=self.port)

    def log(self, level, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report.append(f"[{timestamp}] [{level}] {message}")

    def connect(self):
        if not self.client.connect():
            self.log("ERROR", "Modbus connection failed")
            return False
        return True

    def disconnect(self):
        self.client.close()

    def scan(self):
        if not self.connect():
            return "\n".join(self.report)

        self.modbus_read_device_id()
        self.modbus_bulk_register_scan()
        self.modbus_test_writable_coils()
        self.modbus_test_illegal_writes()

        self.disconnect()
        return "\n".join(self.report)

    def modbus_read_device_id(self):
        try:
            result = self.client.read_holding_registers(address=0, count=4, slave=1)
            if result.isError():
                self.log("INFO", "Device ID read returned error")
            else:
                self.log("INFO", f"Device ID holding register data: {result.registers}")
        except Exception as e:
            self.log("ERROR", f"Device ID read failed: {e}")

    def modbus_bulk_register_scan(self, start=0, end=0x100, step=10):
        for addr in range(start, end, step):
            try:
                result = self.client.read_holding_registers(address=addr, count=step, slave=1)
                if result and not result.isError():
                    self.log("INFO", f"Holding Register {hex(addr)} OK: {result.registers}")
            except ModbusIOException:
                self.log("INFO", f"Holding Register {hex(addr)} not readable")
            except Exception as e:
                self.log("ERROR", f"Scan at {hex(addr)} failed: {e}")

    def modbus_test_writable_coils(self, start=0, count=5):
        for i in range(start, start + count):
            try:
                if self.test_mode:
                    self.log("TEST", f"Skipping write to coil {i} (test mode)")
                    continue

                result = self.client.write_coil(i, True)
                if hasattr(result, 'isError') and result.isError():
                    self.log("PASS", f"Write to coil {i} blocked (expected)")
                else:
                    self.log("CRITICAL", f"Write to coil {i} succeeded! Potential trip risk")
            except Exception as e:
                self.log("ERROR", f"Write to coil {i} failed: {e}")

    def modbus_test_illegal_writes(self, start=0x200, count=5):
        for i in range(start, start + count):
            try:
                if self.test_mode:
                    self.log("TEST", f"Skipping illegal write to {i} (test mode)")
                    continue

                result = self.client.write_register(address=i, value=12345, slave=1)
                if hasattr(result, 'isError') and result.isError():
                    self.log("PASS", f"Illegal register write {i} blocked (expected)")
                else:
                    self.log("WARN", f"Illegal register write {i} accepted")
            except Exception as e:
                self.log("ERROR", f"Illegal write to register {i} failed: {e}")

if __name__ == "__main__":
    target_ip = "10.190.42.105"  # Replace with the IP of your SEL-787 relay
    scanner = SEL787Scanner(target_ip, test_mode=False)
    report = scanner.scan()
    print("\n--- SEL-787 Vulnerability Scan Report ---\n")
    print(report)
