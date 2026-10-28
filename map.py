#!/usr/bin/env python3

import csv
import os
import re
import select
import signal
import socket
import subprocess
import sys
import termios
import time
import tty

from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

CSV_FILE = "network_services.csv"

INTERFACE = "any"

REFRESH_INTERVAL = 1.0

CSV_SAVE_INTERVAL = 10.0

FLOW_TIMEOUT = 3600

MAX_DISPLAY_FLOWS = 30


# ============================================================
# NETTOP
# ============================================================

class NetTop:

    def __init__(self):

        self.running = True
        self.tcpdump = None

        self.flows = {}

        self.total_packets = 0
        self.total_bytes = 0

        self.rx_packets = 0
        self.tx_packets = 0

        self.rx_bytes = 0
        self.tx_bytes = 0

        self.previous_rx_bytes = 0
        self.previous_tx_bytes = 0

        self.previous_time = time.monotonic()

        self.last_refresh = 0
        self.last_csv_save = 0
        self.last_ip_refresh = 0

        self.local_ips = set()

        self.service_cache = {}

        self.old_terminal = None

    # ========================================================
    # SIGNAL HANDLER
    # ========================================================

    def handle_signal(self, signum, frame):
        self.running = False

    # ========================================================
    # TERMINAL
    # ========================================================

    @staticmethod
    def clear_screen():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

    @staticmethod
    def hide_cursor():
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

    @staticmethod
    def show_cursor():
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    # ========================================================
    # LOCAL IPs
    # ========================================================

    @staticmethod
    def get_local_ips():

        try:

            output = subprocess.check_output(
                [
                    "ip",
                    "-4",
                    "-o",
                    "addr",
                    "show"
                ],
                text=True,
                stderr=subprocess.DEVNULL
            )

            ips = set()

            for line in output.splitlines():

                parts = line.split()

                if len(parts) >= 4:

                    ips.add(
                        parts[3].split("/")[0]
                    )

            return ips

        except (OSError, subprocess.SubprocessError):

            return set()

    # ========================================================
    # SERVICE LOOKUP
    # ========================================================

    def get_service(self, port, protocol):

        if port in ("", "-", None):
            return "-"

        try:
            port = int(port)
        except (ValueError, TypeError):
            return "-"

        key = (port, protocol)

        if key in self.service_cache:
            return self.service_cache[key]

        try:

            service = socket.getservbyport(
                port,
                protocol.lower()
            )

        except OSError:

            service = "-"

        self.service_cache[key] = service

        return service

    # ========================================================
    # ENDPOINT PARSER
    # ========================================================

    @staticmethod
    def parse_endpoint(endpoint):

        endpoint = endpoint.rstrip(":")

        match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\.(\d+)$",
            endpoint
        )

        if match:

            return (
                match.group(1),
                match.group(2)
            )

        return endpoint, "-"

    # ========================================================
    # PACKET PARSER
    # ========================================================

    def parse_packet(self, line):

        try:

            if " > " not in line:
                return None

            parts = line.split()

            # ------------------------------------------------
            # Protocol
            # ------------------------------------------------

            # With "tcpdump -q", TCP lines read "... > a.b.c.d.port: tcp 52"
            # (no "Flags"), so match the keyword as well.
            if "Flags" in line or re.search(
                r"\btcp\b",
                line,
                re.IGNORECASE
            ):

                protocol = "TCP"

            elif re.search(
                r"\budp\b",
                line,
                re.IGNORECASE
            ):

                protocol = "UDP"

            elif re.search(
                r"\bicmp\b",
                line,
                re.IGNORECASE
            ):

                protocol = "ICMP"

            else:

                return None

            # ------------------------------------------------
            # Find arrow
            # ------------------------------------------------

            try:

                arrow_index = parts.index(">")

            except ValueError:

                return None

            if arrow_index <= 0:
                return None

            src_raw = parts[arrow_index - 1]

            dst_raw = parts[arrow_index + 1]

            src_ip, src_port = self.parse_endpoint(
                src_raw
            )

            dst_ip, dst_port = self.parse_endpoint(
                dst_raw
            )

            # ------------------------------------------------
            # Direction
            # ------------------------------------------------

            if src_ip in self.local_ips:

                direction = "OUT"

            elif dst_ip in self.local_ips:

                direction = "IN"

            else:

                return None

            # ------------------------------------------------
            # Packet size
            # ------------------------------------------------

            packet_size = 0

            match = re.search(
                r"(?:\blength|\btcp)\s+(\d+)",
                line,
                re.IGNORECASE
            )

            if match:

                packet_size = int(
                    match.group(1)
                )

            return {
                "direction": direction,
                "protocol": protocol,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "bytes": packet_size
            }

        except (ValueError, IndexError):

            return None

    # ========================================================
    # FLOW KEY
    # ========================================================

    @staticmethod
    def make_flow_key(packet):

        if packet["direction"] == "OUT":

            local_port = packet["src_port"]
            remote_ip = packet["dst_ip"]
            remote_port = packet["dst_port"]

        else:

            local_port = packet["dst_port"]
            remote_ip = packet["src_ip"]
            remote_port = packet["src_port"]

        return (
            packet["direction"],
            packet["protocol"],
            local_port,
            remote_ip,
            remote_port
        )

    # ========================================================
    # PROCESS PACKET
    # ========================================================

    def process_packet(self, packet):

        now = time.monotonic()

        key = self.make_flow_key(packet)

        if key not in self.flows:

            self.flows[key] = {
                "direction": packet["direction"],
                "protocol": packet["protocol"],
                "local_port": (
                    packet["src_port"]
                    if packet["direction"] == "OUT"
                    else packet["dst_port"]
                ),
                "remote_ip": (
                    packet["dst_ip"]
                    if packet["direction"] == "OUT"
                    else packet["src_ip"]
                ),
                "remote_port": (
                    packet["dst_port"]
                    if packet["direction"] == "OUT"
                    else packet["src_port"]
                ),
                "packets": 0,
                "bytes": 0,
                "first_seen": now,
                "last_seen": now
            }

        flow = self.flows[key]

        flow["packets"] += 1
        flow["bytes"] += packet["bytes"]
        flow["last_seen"] = now

        self.total_packets += 1
        self.total_bytes += packet["bytes"]

        if packet["direction"] == "IN":

            self.rx_packets += 1
            self.rx_bytes += packet["bytes"]

        else:

            self.tx_packets += 1
            self.tx_bytes += packet["bytes"]

    # ========================================================
    # TCPDUMP
    # ========================================================

    @staticmethod
    def start_tcpdump():

        return subprocess.Popen(
            [
                "tcpdump",
                "-i",
                INTERFACE,
                "-n",
                "-l",
                "-tt",
                "-q"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )

    # ========================================================
    # CLEANUP
    # ========================================================

    def cleanup_flows(self):

        now = time.monotonic()

        expired = [
            key
            for key, flow in self.flows.items()
            if now - flow["last_seen"] > FLOW_TIMEOUT
        ]

        for key in expired:
            del self.flows[key]

    # ========================================================
    # SAVE CSV
    # ========================================================

    def save_csv(self):

        temporary_file = CSV_FILE + ".tmp"

        try:

            with open(
                temporary_file,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)

                writer.writerow([
                    "direction",
                    "protocol",
                    "local_port",
                    "local_service",
                    "remote_ip",
                    "remote_port",
                    "remote_service",
                    "packets",
                    "bytes",
                    "first_seen",
                    "last_seen"
                ])

                for flow in self.flows.values():

                    protocol = flow["protocol"]

                    local_port = flow["local_port"]

                    remote_port = flow["remote_port"]

                    writer.writerow([
                        flow["direction"],
                        protocol,
                        local_port,
                        self.get_service(
                            local_port,
                            protocol
                        ),
                        flow["remote_ip"],
                        remote_port,
                        self.get_service(
                            remote_port,
                            protocol
                        ),
                        flow["packets"],
                        flow["bytes"],
                        datetime.fromtimestamp(
                            flow["first_seen"]
                        ).isoformat(),
                        datetime.fromtimestamp(
                            flow["last_seen"]
                        ).isoformat()
                    ])

                file.flush()
                os.fsync(file.fileno())

            os.replace(
                temporary_file,
                CSV_FILE
            )

        except OSError as exc:

            print(
                f"CSV error: {exc}",
                file=sys.stderr
            )

    # ========================================================
    # FORMAT BYTES
    # ========================================================

    @staticmethod
    def format_bytes(value):

        value = float(value)

        for unit in (
            "B",
            "KB",
            "MB",
            "GB",
            "TB"
        ):

            if value < 1024:

                return f"{value:.1f}{unit}"

            value /= 1024

        return f"{value:.1f}PB"

    # ========================================================
    # RESET
    # ========================================================

    def reset(self):

        self.flows.clear()

        self.total_packets = 0
        self.total_bytes = 0

        self.rx_packets = 0
        self.tx_packets = 0

        self.rx_bytes = 0
        self.tx_bytes = 0

        self.previous_rx_bytes = 0
        self.previous_tx_bytes = 0

        self.save_csv()

    # ========================================================
    # DASHBOARD
    # ========================================================

    def render(self, rx_rate, tx_rate):

        self.clear_screen()

        print(
            "\033[1;36mNETTOP\033[0m"
            f"   {datetime.now():%Y-%m-%d %H:%M:%S}"
        )

        print()

        print(f"Interface : {INTERFACE}")

        print(
            "Local IPs : "
            + ", ".join(sorted(self.local_ips))
        )

        print()

        print(
            f"RX {self.format_bytes(rx_rate)}/s    "
            f"TX {self.format_bytes(tx_rate)}/s    "
            f"Flows {len(self.flows):,}    "
            f"Packets {self.total_packets:,}    "
            f"Traffic {self.format_bytes(self.total_bytes)}"
        )

        print()

        print(
            f"{'DIR':<5}"
            f"{'PROTO':<7}"
            f"{'LOCAL':<12}"
            f"{'REMOTE':<26}"
            f"{'SERVICE':<18}"
            f"{'PACKETS':>10}"
            f"{'BYTES':>12}"
        )

        print("-" * 100)

        sorted_flows = sorted(
            self.flows.values(),
            key=lambda flow: flow["bytes"],
            reverse=True
        )

        for flow in sorted_flows[:MAX_DISPLAY_FLOWS]:

            local_port = flow["local_port"]

            remote = (
                f"{flow['remote_ip']}:"
                f"{flow['remote_port']}"
            )

            service = self.get_service(
                local_port,
                flow["protocol"]
            )

            print(
                f"{flow['direction']:<5}"
                f"{flow['protocol']:<7}"
                f":{local_port:<11}"
                f"{remote:<26}"
                f"{service:<18}"
                f"{flow['packets']:>10,}"
                f"{self.format_bytes(flow['bytes']):>12}"
            )

        print()

        print(
            "\033[90m"
            "q: quit    "
            "r: reset    "
            f"CSV: {CSV_FILE}"
            "\033[0m"
        )

    # ========================================================
    # STOP
    # ========================================================

    def stop(self):

        self.running = False

        if self.tcpdump is not None:

            try:
                self.tcpdump.terminate()
                self.tcpdump.wait(timeout=2)

            except subprocess.TimeoutExpired:

                self.tcpdump.kill()

            except OSError:
                pass

        self.save_csv()

        if self.old_terminal is not None:

            try:

                termios.tcsetattr(
                    sys.stdin,
                    termios.TCSADRAIN,
                    self.old_terminal
                )

            except termios.error:
                pass

        self.show_cursor()

    # ========================================================
    # RUN
    # ========================================================

    def run(self):

        if os.geteuid() != 0:

            print(
                f"Run with: sudo {sys.argv[0]}"
            )

            return 1

        self.local_ips = self.get_local_ips()

        if not self.local_ips:

            print(
                "Could not determine local IP addresses."
            )

            return 1

        self.old_terminal = termios.tcgetattr(
            sys.stdin
        )

        tty.setcbreak(
            sys.stdin.fileno()
        )

        self.hide_cursor()

        signal.signal(
            signal.SIGINT,
            self.handle_signal
        )

        signal.signal(
            signal.SIGTERM,
            self.handle_signal
        )

        self.tcpdump = self.start_tcpdump()

        self.last_refresh = 0
        self.last_csv_save = 0
        self.last_ip_refresh = 0

        try:

            while self.running:

                # --------------------------------------------
                # Read tcpdump
                # --------------------------------------------

                if self.tcpdump.poll() is not None:

                    time.sleep(1)

                    if self.running:

                        self.tcpdump = (
                            self.start_tcpdump()
                        )

                    continue

                readable, _, _ = select.select(
                    [self.tcpdump.stdout],
                    [],
                    [],
                    0.1
                )

                if readable:

                    line = self.tcpdump.stdout.readline()

                    if line:

                        packet = self.parse_packet(
                            line
                        )

                        if packet:

                            self.process_packet(
                                packet
                            )

                # --------------------------------------------
                # Keyboard
                # --------------------------------------------

                if select.select(
                    [sys.stdin],
                    [],
                    [],
                    0
                )[0]:

                    key = sys.stdin.read(1)

                    if key.lower() == "q":

                        self.running = False

                    elif key.lower() == "r":

                        self.reset()

                now = time.monotonic()

                # --------------------------------------------
                # IP refresh
                # --------------------------------------------

                if (
                    now - self.last_ip_refresh
                    >= 10
                ):

                    self.local_ips = (
                        self.get_local_ips()
                    )

                    self.last_ip_refresh = now

                # --------------------------------------------
                # Dashboard
                # --------------------------------------------

                if (
                    now - self.last_refresh
                    >= REFRESH_INTERVAL
                ):

                    elapsed = (
                        now - self.previous_time
                    )

                    if elapsed <= 0:
                        elapsed = 1

                    rx_rate = (
                        self.rx_bytes
                        - self.previous_rx_bytes
                    ) / elapsed

                    tx_rate = (
                        self.tx_bytes
                        - self.previous_tx_bytes
                    ) / elapsed

                    self.render(
                        rx_rate,
                        tx_rate
                    )

                    self.previous_rx_bytes = (
                        self.rx_bytes
                    )

                    self.previous_tx_bytes = (
                        self.tx_bytes
                    )

                    self.previous_time = now

                    self.last_refresh = now

                # --------------------------------------------
                # CSV
                # --------------------------------------------

                if (
                    now - self.last_csv_save
                    >= CSV_SAVE_INTERVAL
                ):

                    self.cleanup_flows()

                    self.save_csv()

                    self.last_csv_save = now

        finally:

            self.stop()

        return 0


# ============================================================
# ENTRY POINT
# ============================================================

def main():

    application = NetTop()

    return application.run()


if __name__ == "__main__":

    sys.exit(main())
