from pymodbus.client import ModbusTcpClient
# from pydnp3 import opendnp3, asiodnp3  # Commented out until DNP3 logic is ready
# from pyiec61850.client import IEDClient  # Commented out for now, focusing on Modbus only

class SEL787Scanner:
    def __init__(self, ip):
        self.ip = ip
        self.report = []

    def scan(self):
        self.modbus_device_id()
        self.modbus_writable_coil()
        # self.dnp3_device_attributes()  # DNP3 check commented out for now
        # self.iec61850_logical_node_discovery()  # IEC 61850 check commented out for now
        return "\n".join(self.report)

    def modbus_device_id(self):
        client = ModbusTcpClient(self.ip)
        if not client.connect():
            self.report.append("[Modbus] ERROR: Connection failed")
            return

        try:
            # result = client.execute(
            #     0x2B, 0x0E, 0x01, 0x00, unit=1
            # )  # Function 43/14 request
            result = client.read_holding_registers(0x00)
            if result:
                self.report.append(f"[Modbus] INFO: Device ID Response: {result}")
            else:
                self.report.append("[Modbus] INFO: No Device ID response.")
        except Exception as e:
            self.report.append(f"[Modbus] ERROR: {e}")
        finally:
            client.close()

    def modbus_writable_coil(self, test_coil=1):
        client = ModbusTcpClient(self.ip)
        if not client.connect():
            self.report.append("[Modbus] ERROR: Connection failed (writable coil test)")
            return

        try:
            result = client.write_coil(test_coil, True)
            if hasattr(result, 'isError') and result.isError():
                self.report.append("[Modbus] PASS: Coil write blocked (expected behavior)")
            else:
                self.report.append("[Modbus] CRITICAL: Coil write accepted! Remote trip possible.")
        except Exception as e:
            self.report.append(f"[Modbus] ERROR: {e}")
        finally:
            client.close()

    # def dnp3_device_attributes(self):
    #     # Placeholder: Full DNP3 implementation would use pydnp3 Master stack
    #     self.report.append("[DNP3] INFO: Simulated device attribute check (implement stack)")

    # def iec61850_logical_node_discovery(self):
#     try:
#         client = IEDClient(self.ip, 102)
#         client.connect()
#         nodes = client.getLogicalDeviceNames()
#
#         if nodes:
#             self.report.append(f"[IEC61850] WARNING: Logical Devices visible without auth: {nodes}")
#         else:
#             self.report.append("[IEC61850] PASS: No logical devices visible or properly secured.")
#     except Exception as e:
#         self.report.append(f"[IEC61850] ERROR: {e}")
#     finally:
#         try:
#             client.disconnect()
#         except:
#             pass

# Example Usage:
if __name__ == "__main__":
    target_ip = "10.190.42.105"  # Replace with your relay IP
    scanner = SEL787Scanner(target_ip)
    results = scanner.scan()
    print("\n--- SEL-787 Vulnerability Scan Report ---\n")
    print(results)
