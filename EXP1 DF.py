import os
import time
from datetime import datetime
from pathlib import Path

# ----------------------------------------------------
# Digital Forensics Demonstration
# Locard's Exchange Principle using File Timestamps
# ----------------------------------------------------

TEST_FILE = "forensic_test.txt"


def format_time(timestamp):
    """Convert UNIX timestamp to readable date/time."""
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def collect_metadata(file_path):
    """
    Collect available timestamp metadata.
    """
    stats = os.stat(file_path)

    metadata = {
        "Observation Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Creation Time": getattr(stats, "st_birthtime", stats.st_ctime),
        "Modification Time": stats.st_mtime,
        "Access Time": stats.st_atime
    }

    return metadata


def print_metadata(title, metadata):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

    print("Observed Facts")
    print(f"Observation Date/Time : {metadata['Observation Time']}")
    print(f"Creation Timestamp    : {format_time(metadata['Creation Time'])}")
    print(f"Modification Timestamp: {format_time(metadata['Modification Time'])}")
    print(f"Access Timestamp      : {format_time(metadata['Access Time'])}")


def compare(before, after):
    print("\n" + "=" * 60)
    print("Comparison of Metadata")
    print("=" * 60)

    changed = False

    for field in ["Creation Time", "Modification Time", "Access Time"]:
        if before[field] != after[field]:
            changed = True
            print(f"\n{field}")
            print(f"  Before: {format_time(before[field])}")
            print(f"  After : {format_time(after[field])}")
        else:
            print(f"\n{field}")
            print("  No change observed.")

    print("\n" + "=" * 60)
    print("Forensic Interpretation")
    print("=" * 60)

    print("The following statements are interpretations, not direct observations.")

    if before["Modification Time"] != after["Modification Time"]:
        print("- The file contents were likely modified after the initial observation.")

    if before["Access Time"] != after["Access Time"]:
        print("- The file appears to have been accessed between observations.")

    if before["Creation Time"] != after["Creation Time"]:
        print("- The creation/metadata timestamp changed.")
        print("  On some operating systems this reflects metadata changes")
        print("  rather than the original file creation time.")

    if not changed:
        print("- No timestamp changes were detected.")
        print("  This does not necessarily prove that no interaction occurred,")
        print("  because operating-system settings may suppress timestamp updates.")

    print("\nLocard's Exchange Principle Demonstration:")
    print("Interaction with digital evidence can leave traces in filesystem")
    print("metadata. Timestamp differences provide observable artifacts that")
    print("may assist a forensic examiner when reconstructing events.")


def main():

    # Create the test file if it does not exist
    if not Path(TEST_FILE).exists():
        with open(TEST_FILE, "w") as f:
            f.write("Initial forensic demonstration file.\n")

    print("Collecting initial metadata...")
    before = collect_metadata(TEST_FILE)
    print_metadata("Initial Observation", before)

    # Pause so timestamp differences are visible
    time.sleep(2)

    # Controlled interaction:
    # 1. Read the file
    with open(TEST_FILE, "r") as f:
        _ = f.read()

    # Pause
    time.sleep(2)

    # 2. Append evidence
    with open(TEST_FILE, "a") as f:
        f.write(f"Controlled modification at {datetime.now()}\n")

    # Ensure filesystem flush
    time.sleep(2)

    print("\nCollecting metadata after controlled interaction...")
    after = collect_metadata(TEST_FILE)
    print_metadata("Second Observation", after)

    compare(before, after)


if __name__ == "__main__":
    main()
