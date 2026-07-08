"""
==========================================================
Process Monitor - Version 1
Self-Evolving Security AI

Part 1

Features
--------
✓ Continuous process monitoring
✓ Tracks process creation
✓ Tracks process termination
✓ Keeps process cache in memory
✓ Low CPU usage
==========================================================
"""

import time
from datetime import datetime

import psutil

from database.db import get_connection, close_connection


class ProcessMonitor:

    def __init__(self, interval=2):
        """
        interval
            Scan interval in seconds.
        """

        self.interval = interval

        # PID -> Process Information
        self.known_processes = {}

        self.running = True

    # -------------------------------------------------
    # Collect information about one process
    # -------------------------------------------------

    def get_process_info(self, process):
        """
        Safely collect information about a process.

        Returns
        -------
        dict
        """

        try:

            pid = process.pid

            parent_pid = process.ppid()

            process_name = process.name()

            # CPU usage (first value may be 0.0)
            cpu_usage = process.cpu_percent(interval=None)

            # Memory in MB
            memory_usage = round(
                process.memory_info().rss / (1024 * 1024),
                2
            )

            # Command Line
            try:
                command_line = " ".join(process.cmdline())
            except Exception:
                command_line = ""

            # Process Start Time
            try:
                start_time = datetime.fromtimestamp(
                    process.create_time()
                ).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                start_time = ""

            return {

                "pid": pid,

                "parent_pid": parent_pid,

                "process_name": process_name,

                "cpu_usage": cpu_usage,

                "memory_usage": memory_usage,

                "command_line": command_line,

                "start_time": start_time

            }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            return None

    # -------------------------------------------------
    # Scan every running process
    # -------------------------------------------------

    def scan_processes(self):
        """
        Returns

        {
            PID : process_information
        }
        """

        current_processes = {}

        for process in psutil.process_iter():

            info = self.get_process_info(process)

            if info is None:
                continue

            current_processes[info["pid"]] = info

        return current_processes

    # -------------------------------------------------
    # Display event
    # -------------------------------------------------

    def print_event(self,event_type,process):
        print(
            f"[{event_type}] "
            f"{process['process_name']:<30}"
            f"PID:{process['pid']:<8}"
            f"CPU:{process['cpu_usage']:<6.1f}% "
            f"MEM:{process['memory_usage']:<8.2f} MB"
        )

    # -------------------------------------------------
    # Save process event
    #
    # Part 2 will implement this.
    # -------------------------------------------------

    def save_event(self,event_type,process):
    
        conn = None

        try:

            conn = get_connection()
            cursor = conn.cursor()

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            cursor.execute(
                """
                INSERT INTO process_events
                (
                    timestamp,
                    event_type,
                    pid,
                    parent_pid,
                    process_name,
                    cpu_usage,
                    memory_usage,
                    command_line,
                    start_time
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    event_type,
                    process["pid"],
                    process["parent_pid"],
                    process["process_name"],
                    process["cpu_usage"],
                    process["memory_usage"],
                    process["command_line"],
                    process["start_time"]
                )
            )   

            conn.commit()

        except Exception as e:

            print(f"[DATABASE ERROR] {e}")

        finally:

            if conn:
                close_connection(conn)

        # -------------------------------------------------
        # Detect new processes
        #
        # Part 2 will implement this.
        # -------------------------------------------------

    def detect_new_processes(self,current_processes):
        """
        Detect newly created processes.
        """

        for pid, process in current_processes.items():

            # New process found
            if pid not in self.known_processes:

                self.print_event(
                    "PROCESS_CREATED",
                    process
                )

                self.save_event(
                    "PROCESS_CREATED",
                    process
                )

    # -------------------------------------------------
    # Detect terminated processes
    #
    # Part 2 will implement this.
    # -------------------------------------------------

    def detect_terminated_processes(self,current_processes):
        """
        Detect processes that have terminated.
        """

        for pid, process in self.known_processes.items():

            # Process no longer exists
            if pid not in current_processes:

                self.print_event(
                    "PROCESS_TERMINATED",
                    process
                )

                self.save_event(
                    "PROCESS_TERMINATED",
                    process
                )

        # -------------------------------------------------
        # Monitor forever
        #
        # Part 2 will implement this.
        # -------------------------------------------------

    def monitor(self):
        """
        Continuously monitor processes.
        """

        print("=" * 60)
        print("Self-Evolving Security AI - Process Monitor")
        print(f"Scan Interval : {self.interval} second(s)")
        print("Press Ctrl + C to stop.")
        print("=" * 60)

        # -------------------------
        # Initial Scan
        # -------------------------
        print("\nPerforming initial scan...")

        self.known_processes = self.scan_processes()

        print(
            f"Loaded {len(self.known_processes)} running processes into memory.\n"
        )

        # -------------------------
        # Continuous Monitoring
        # -------------------------
        try:

            while self.running:

                current_processes = self.scan_processes()

                # Detect newly created processes
                self.detect_new_processes(current_processes)

                # Detect terminated processes
                self.detect_terminated_processes(current_processes)

                # Update cache
                self.known_processes = current_processes

                # Wait before next scan
                for _ in range(int(self.interval * 10)):
                    if not self.running:
                        break
                time.sleep(0.1)

        finally:
            print("[PROCESS MONITOR] Stopped.")


if __name__ == "__main__":

    monitor = ProcessMonitor(interval=2)

    monitor.monitor()