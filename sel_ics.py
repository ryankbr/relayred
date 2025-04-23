from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusIOException
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

class SEL787Scanner:
    def __init__(self, ip, port=502, test_mode=False):
        self.ip = ip
        self.port = port
        self.test_mode = test_mode
        self.report = []
        self.console = Console()
        self.client = ModbusTcpClient(self.ip, port=self.port)
        self.register_data = []
        self.coil_data = []
        self.discrete_input_data = []
        self.input_register_data = []

    def log(self, level, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{level}] {message}"
        self.report.append(entry)

    def connect(self):
        if not self.client.connect():
            self.log("ERROR", "Modbus connection failed")
            return False
        return True

    def disconnect(self):
        self.client.close()

    def scan(self):
        if not self.connect():
            return self.finalize()

        self.modbus_read_device_id()
        self.modbus_bulk_register_scan()
        self.modbus_read_coils()
        self.modbus_read_discrete_inputs()
        self.modbus_read_input_registers()
        self.disconnect()
        return self.finalize()

    def finalize(self):
        with open("ics_results.txt", "w") as f:
            for line in self.report:
                f.write(line + "\n")
        self.display_table("Registers", self.register_data)
        self.display_table("Coils", self.coil_data)
        self.display_table("Discrete Inputs", self.discrete_input_data)
        self.display_table("Input Registers", self.input_register_data)
        return "\n".join(self.report)

    def display_table(self, title, data):
        if not data:
            return
        table = Table(title=title, box=box.SIMPLE_HEAVY, expand=False, show_lines=False, padding=(0, 1))
        for _ in range(3):
            table.add_column("Label", style="cyan", no_wrap=True, max_width=20)
            table.add_column("Value", style="magenta", no_wrap=True, max_width=12)
        row = []
        for label, value in data:
            if label.startswith("Reg ") or label.startswith("Input Register ") or label.startswith("Coil ") or label.startswith("Discrete Input "):
                continue
            display_value = f"[bold red]{value}[/bold red]" if value == "ON" or (isinstance(value, (int, float)) and value > 1000) else str(value)
            row.extend([label, display_value])
            if len(row) == 6:
                table.add_row(*row)
                row = []
        if row:
            row += ["", ""] * ((6 - len(row)) // 2)
            table.add_row(*row)
        self.console.print(Panel(table, border_style="green", expand=False))

    def modbus_read_device_id(self):
        try:
            result = self.client.read_holding_registers(address=0, count=4, slave=1)
            if result.isError():
                self.log("INFO", "Device ID read returned error")
            else:
                values = result.registers
                self.log("INFO", f"Device ID holding register data: {values}")
        except Exception as e:
            self.log("ERROR", f"Device ID read failed: {e}")

    def modbus_bulk_register_scan(self, start=0, end=0x32c, step=10):
        known_labels = {
            684: "IAW1_MAG", 685: "IAW1_ANG", 686: "IBW1_MAG", 687: "IBW1_ANG",
            688: "ICW1_MAG", 689: "ICW1_ANG", 690: "IGW1_MAG", 691: "IGW1_ANG",
            692: "3I2W1MAG", 693: "IAVW1MAG", 694: "IAW2_MAG", 695: "IAW2_ANG",
            696: "IBW2_MAG", 697: "IBW2_ANG", 698: "ICW2_MAG", 699: "ICW2_ANG",
            700: "IGW2_MAG", 701: "IGW2_ANG", 702: "3I2W2MAG", 703: "IAVW2MAG",
            704: "IN_MAG", 705: "IN_ANG", 709: "VAB_MAG", 710: "VAB_ANG",
            711: "VBC_MAG", 712: "VBC_ANG", 713: "VCA_MAG", 714: "VCA_ANG",
            715: "VAVE_MAG", 716: "VA_MAG", 717: "VA_ANG", 718: "VB_MAG",
            719: "VB_ANG", 720: "VC_MAG", 721: "VC_ANG", 722: "VG_MAG",
            723: "VG_ANG", 724: "VAVE_MAG", 725: "3V2_MAG", 726: "P",
            727: "Q", 728: "S", 729: "PF", 730: "VHZ", 731: "FREQ",
            770: "IAW1_THD", 771: "IBW1_THD", 772: "ICW1_THD", 773: "IAW2_THD",
            774: "IBW2_THD", 775: "ICW2_THD", 776: "VA_THD", 777: "VB_THD",
            778: "VC_THD", 779: "VAB_THD", 780: "VBC_THD", 781: "VCA_THD",
            782: "RTDAMB", 783: "RTDOTHMX", 784: "RTD1", 785: "RTD2",
            786: "RTD3", 787: "RTD4", 788: "RTD5", 789: "RTD6",
            790: "RTD7", 791: "RTD8", 792: "RTD9", 793: "RTD10",
            794: "RTD11", 795: "RTD12", 807: "IAW1RMS", 808: "IBW1RMS",
            809: "ICW1RMS", 810: "IAW2RMS", 811: "IBW2RMS", 812: "ICW2RMS",
            813: "INRMS", 814: "VARMS", 815: "VBRMS", 816: "VCRMS",
            817: "VABRMS", 818: "VBCRMS", 819: "VCARMS"
        }
        for addr in range(start, end, step):
            try:
                result = self.client.read_holding_registers(address=addr, count=step, slave=1)
                if result and not result.isError():
                    for i, val in enumerate(result.registers):
                        reg_addr = addr + i
                        label = known_labels.get(reg_addr)
                        if not label:
                            continue
                        if "MAG" in label or "THD" in label:
                            value = val * 0.1
                        elif "FREQ" in label or "PF" in label:
                            value = val * 0.01
                        elif "RMS" in label or "RTD" in label:
                            value = val * 0.1
                        else:
                            value = val
                        self.register_data.append((label, value))
            except Exception as e:
                self.log("ERROR", f"Scan at {hex(addr)} failed: {e}")

    def modbus_read_coils(self, start=0, count=91):
        known_coils = {
            0: "OUT101 (1s Pulse)", 1: "OUT102 (1s Pulse)", 2: "OUT103 (1s Pulse)",
            3: "OUT301 (1s Pulse)", 4: "OUT302 (1s Pulse)", 5: "OUT303 (1s Pulse)", 6: "OUT304 (1s Pulse)",
            11: "OUT401 (1s Pulse)", 12: "OUT402 (1s Pulse)", 13: "OUT403 (1s Pulse)", 14: "OUT404 (1s Pulse)",
            19: "OUT501 (1s Pulse)", 20: "OUT502 (1s Pulse)", 21: "OUT503 (1s Pulse)", 22: "OUT504 (1s Pulse)",
            27: "RB01", 28: "RB02", 29: "RB03", 30: "RB04", 31: "RB05", 32: "RB06", 33: "RB07", 34: "RB08",
            35: "RB09", 36: "RB10", 37: "RB11", 38: "RB12", 39: "RB13", 40: "RB14", 41: "RB15", 42: "RB16",
            43: "RB17", 44: "RB18", 45: "RB19", 46: "RB20", 47: "RB21", 48: "RB22", 49: "RB23", 50: "RB24",
            51: "RB25", 52: "RB26", 53: "RB27", 54: "RB28", 55: "RB29", 56: "RB30", 57: "RB31", 58: "RB32",
            59: "Pulse RB01", 60: "Pulse RB02", 61: "Pulse RB03", 62: "Pulse RB04", 63: "Pulse RB05",
            64: "Pulse RB06", 65: "Pulse RB07", 66: "Pulse RB08", 67: "Pulse RB09", 68: "Pulse RB10",
            69: "Pulse RB11", 70: "Pulse RB12", 71: "Pulse RB13", 72: "Pulse RB14", 73: "Pulse RB15",
            74: "Pulse RB16", 75: "Pulse RB17", 76: "Pulse RB18", 77: "Pulse RB19", 78: "Pulse RB20",
            79: "Pulse RB21", 80: "Pulse RB22", 81: "Pulse RB23", 82: "Pulse RB24", 83: "Pulse RB25",
            84: "Pulse RB26", 85: "Pulse RB27", 86: "Pulse RB28", 87: "Pulse RB29", 88: "Pulse RB30",
            89: "Pulse RB31", 90: "Pulse RB32"
        }
        try:
            result = self.client.read_coils(address=start, count=count, slave=1)
            if result and not result.isError():
                for i, bit in enumerate(result.bits):
                    addr = start + i
                    if addr in known_coils:
                        label = known_coils[addr]
                        status = "ON" if bit else "OFF"
                        self.coil_data.append((label, status))
        except Exception as e:
            self.log("ERROR", f"Coil read failed: {e}")

    def modbus_read_discrete_inputs(self, start=0, count=16):
        known_inputs = {
            0: "IN11 / IN301 Status", 1: "IN12 / IN302 Status",
            2: "IN13 / IN303 Status", 3: "IN14 / IN304 Status",
            4: "IN15 / IN305 Status", 5: "IN16 / IN306 Status",
            6: "IN17 / IN307 Status", 7: "IN18 / IN308 Status",
            8: "IN21 / IN401 Status", 9: "IN22 / IN402 Status",
            10: "IN23 / IN403 Status", 11: "IN24 / IN404 Status",
            12: "IN25 / IN405 Status", 13: "IN26 / IN406 Status"
        }
        try:
            result = self.client.read_discrete_inputs(address=start, count=count, slave=1)
            if result and not result.isError():
                for i, bit in enumerate(result.bits):
                    if (start + i) in known_inputs:
                        label = known_inputs[start + i]
                        status = "ON" if bit else "OFF"
                        self.discrete_input_data.append((label, status))
        except Exception as e:
            self.log("ERROR", f"Discrete input read failed: {e}")

    def modbus_read_input_registers(self, start=0x0, end=0x60, step=10):
        known_inputs = {
            0x0002: "MV01–HI", 0x0003: "MV01–LO",
            0x0004: "MV02–HI", 0x0005: "MV02–LO",
            0x0006: "MV03–HI", 0x0007: "MV03–LO",
            0x0008: "MV04–HI", 0x0009: "MV04–LO",
            0x0020: "COUNTER SC01", 0x0021: "COUNTER SC02",
            0x0042: "EVENT LOG SEL", 0x0043: "EVENT LOG PTR",
            0x0044: "EVEMO", 0x0045: "EVEDA", 0x0046: "EVETI",
            0x0047: "EVEMSGHI", 0x0048: "EVEMSGLO"
        }
        for addr in range(start, end, step):
            try:
                result = self.client.read_input_registers(address=addr, count=step, slave=1)
                if result and not result.isError():
                    for i, val in enumerate(result.registers):
                        reg_addr = addr + i
                        if reg_addr in known_inputs:
                            label = known_inputs[reg_addr]
                            self.input_register_data.append((label, val))
            except Exception as e:
                self.log("ERROR", f"Input register scan at {hex(addr)} failed: {e}")

if __name__ == "__main__":
    target_ip = "10.190.42.105"
    scanner = SEL787Scanner(target_ip, test_mode=False)
    scanner.scan()
