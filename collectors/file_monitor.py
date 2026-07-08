"""
==========================================================
File Monitor - Version 1
Self-Evolving Security AI

Part 1A

Features
--------
✓ Real-time file monitoring
✓ AI-ready architecture
✓ Metadata helper functions
==========================================================
"""

import os
import psutil
import time
import uuid
import mimetypes
import getpass
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from database.db import get_connection, close_connection
from collectors.event_types import FileEventType


class FileMonitor(FileSystemEventHandler):
    """
    Real-Time File Monitor

    Version 1
    """

    def __init__(self, watch_path):

        super().__init__()

        self.watch_path = watch_path

        self.observer = Observer()

        self.running = True

    # -------------------------------------------------
    # Return current username
    # -------------------------------------------------

    def get_user_name(self):

        try:
            return getpass.getuser()

        except Exception:
            return None

    # -------------------------------------------------
    # Return drive letter
    # -------------------------------------------------

    def get_drive(self, file_path):

        try:

            drive = os.path.splitdrive(file_path)[0]

            return drive

        except Exception:

            return None

    # -------------------------------------------------
    # Check whether file is executable
    # -------------------------------------------------

    def is_executable(self, file_path):

        executable_extensions = {

            ".exe",
            ".dll",
            ".sys",
            ".bat",
            ".cmd",
            ".com",
            ".scr",
            ".msi",
            ".ps1"

        }

        extension = os.path.splitext(file_path)[1].lower()

        return int(extension in executable_extensions)

    # -------------------------------------------------
    # Detect MIME type
    # -------------------------------------------------

    def get_mime_type(self, file_path):

        try:

            mime_type, _ = mimetypes.guess_type(file_path)

            return mime_type

        except Exception:

            return None

    # -------------------------------------------------
    # Generate unique Event ID
    # -------------------------------------------------

    def generate_event_uuid(self):

        return str(uuid.uuid4())

    # -------------------------------------------------
    # Generate Operation ID
    #
    # Later this will group related events
    # -------------------------------------------------

    def generate_operation_id(self):

        return str(uuid.uuid4())
    
    # -------------------------------------------------
    # Build File Metadata
    # -------------------------------------------------

    def build_file_metadata(
        self,
        file_path,
        is_directory=False,
        old_file_path=None,
        old_file_name=None,
        new_file_name=None
    ):
        """
        Collect metadata for a file or directory.

        Returns
        -------
        dict
        """

        metadata = {}

        # Timestamp
        metadata["timestamp"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # Paths
        metadata["file_path"] = file_path
        metadata["old_file_path"] = old_file_path

        # Names
        metadata["file_name"] = os.path.basename(file_path)
        metadata["old_file_name"] = old_file_name
        metadata["new_file_name"] = new_file_name

        # Extension
        metadata["extension"] = os.path.splitext(file_path)[1]

        # Previous extension (useful for rename analysis)
        if old_file_name:

            metadata["file_extension_before"] = os.path.splitext(
                old_file_name
            )[1]

        else:

            metadata["file_extension_before"] = None

        # File Size
        try:

            if not is_directory:

                metadata["file_size"] = os.path.getsize(file_path)

            else:

                metadata["file_size"] = 0

        except Exception:

            metadata["file_size"] = 0

        # Directory?
        metadata["is_directory"] = int(is_directory)

        # Executable?
        if not is_directory:

            metadata["is_executable"] = self.is_executable(
                file_path
            )

        else:

            metadata["is_executable"] = 0

        # MIME Type
        if not is_directory:

            metadata["mime_type"] = self.get_mime_type(
                file_path
            )

        else:

            metadata["mime_type"] = None

        # Future Feature
        metadata["entropy"] = None

        # Future Process Correlation
        metadata["process_id"] = None
        metadata["process_name"] = None

        # User
        metadata["user_name"] = self.get_user_name()

        # Drive
        metadata["drive"] = self.get_drive(file_path)

        # UUID
        metadata["event_uuid"] = self.generate_event_uuid()

        # Operation ID
        metadata["operation_id"] = self.generate_operation_id()

        return metadata
    
    # -------------------------------------------------
    # Save Event
    # -------------------------------------------------

    def save_event(
        self,
        event_type,
        metadata
    ):
        """
        Save a file event to the SQLite database.
        """

        conn = None

        try:

            conn = get_connection()

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO file_events
                (
                    timestamp,
                    event_type,
                    file_path,
                    old_file_path,
                    file_name,
                    old_file_name,
                    new_file_name,
                    extension,
                    file_size,
                    process_id,
                    process_name,
                    is_directory,
                    is_executable,
                    mime_type,
                    entropy,
                    operation_id,
                    user_name,
                    drive,
                    file_extension_before,
                    event_uuid
                )
                VALUES
                (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    metadata["timestamp"],
                    event_type,
                    metadata["file_path"],
                    metadata["old_file_path"],
                    metadata["file_name"],
                    metadata["old_file_name"],
                    metadata["new_file_name"],
                    metadata["extension"],
                    metadata["file_size"],
                    metadata["process_id"],
                    metadata["process_name"],
                    metadata["is_directory"],
                    metadata["is_executable"],
                    metadata["mime_type"],
                    metadata["entropy"],
                    metadata["operation_id"],
                    metadata["user_name"],
                    metadata["drive"],
                    metadata["file_extension_before"],
                    metadata["event_uuid"]
                )
            )

            conn.commit()

        except Exception as e:

            print(f"[DATABASE ERROR] {e}")

        finally:

            if conn:

                close_connection(conn)
    # -------------------------------------------------
    # File Created
    # -------------------------------------------------

    def on_created(self, event):
        """
        Triggered whenever a file or directory is created.
        """

        metadata = self.build_file_metadata(
            file_path=event.src_path,
            is_directory=event.is_directory
        )

        print(
            f"[{FileEventType.CREATED.value}] "
            f"{event.src_path}"
        )

        self.save_event(
            FileEventType.CREATED.value,
            metadata
        )
    # -------------------------------------------------
    # File Modified
    # -------------------------------------------------

    def on_modified(self, event):
        """
        Triggered whenever a file or directory is modified.
        """

        metadata = self.build_file_metadata(
            file_path=event.src_path,
            is_directory=event.is_directory
        )

        print(
            f"[{FileEventType.MODIFIED.value}] "
            f"{event.src_path}"
        )

        self.save_event(
            FileEventType.MODIFIED.value,
            metadata
        )
    # -------------------------------------------------
    # File Deleted
    # -------------------------------------------------

    def on_deleted(self, event):
        """
        Triggered whenever a file or directory is deleted.
        """

        metadata = {

            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            "file_path": event.src_path,

            "old_file_path": None,

            "file_name": os.path.basename(
                event.src_path
            ),

            "old_file_name": None,

            "new_file_name": None,

            "extension": os.path.splitext(
                event.src_path
            )[1],

            "file_size": 0,

            "process_id": None,

            "process_name": None,

            "is_directory": int(event.is_directory),

            "is_executable": self.is_executable(
                event.src_path
            ) if not event.is_directory else 0,

            "mime_type": None,

            "entropy": None,

            "operation_id": self.generate_operation_id(),

            "user_name": self.get_user_name(),

            "drive": self.get_drive(
                event.src_path
            ),

            "file_extension_before": os.path.splitext(
                event.src_path
            )[1],

            "event_uuid": self.generate_event_uuid()

        }

        print(
            f"[{FileEventType.DELETED.value}] "
            f"{event.src_path}"
        )

        self.save_event(
            FileEventType.DELETED.value,
            metadata
        )
    # -------------------------------------------------
    # File Renamed / Moved
    # -------------------------------------------------

    def on_moved(self, event):
        """
        Triggered whenever a file or directory is renamed
        or moved.
        """

        old_path = event.src_path
        new_path = event.dest_path

        metadata = self.build_file_metadata(
            file_path=new_path,
            is_directory=event.is_directory,
            old_file_path=old_path,
            old_file_name=os.path.basename(old_path),
            new_file_name=os.path.basename(new_path)
        )

        print(
            f"[{FileEventType.RENAMED.value}] "
            f"{old_path}  -->  {new_path}"
        )

        self.save_event(
            FileEventType.RENAMED.value,
            metadata
        )
    # -------------------------------------------------
    # Start Monitoring
    # -------------------------------------------------

        # -------------------------------------------------
    # Discover Drives
    # -------------------------------------------------

    def get_watch_directories(self):
        """
        Automatically discover all mounted drives.

        Includes:
        ✓ Local Drives
        ✓ USB Drives
        ✓ Network Drives (optional)
        """

        watch_directories = []

        for partition in psutil.disk_partitions():

            try:

                # Skip CD/DVD drives
                if "cdrom" in partition.opts.lower():
                    continue

                # Must exist
                if os.path.exists(partition.mountpoint):

                    watch_directories.append(
                        partition.mountpoint
                    )

            except Exception:

                continue

        return watch_directories

    def start(self):
        """
        Start monitoring all discovered drives.
        """

        print("=" * 60)
        print("Self-Evolving Security AI - File Monitor")
        print("=" * 60)
        print("Monitoring Drives:")
        print("=" * 60)

        watch_directories = self.get_watch_directories()

        for directory in watch_directories:

            print(f"   {directory}")

            self.observer.schedule(
                self,
                directory,
                recursive=True
            )

        self.observer.start()

        try:

            while self.running:

                time.sleep(1)

        except KeyboardInterrupt:

            self.stop()

    # -------------------------------------------------
    # Stop Monitoring
    # -------------------------------------------------

    def stop(self):
        """
        Stop monitoring safely.
        """

        print("\n")
        print("=" * 60)
        print("Stopping File Monitor...")
        print("=" * 60)

        self.running = False

        self.observer.stop()

        self.observer.join()

        print("File Monitor stopped successfully.")
# -------------------------------------------------
# Main
# -------------------------------------------------

if __name__ == "__main__":

    monitor = FileMonitor(None)

    monitor.start()