import hashlib
import json
import os
from datetime import datetime



EVIDENCE_FILE = "evidence.txt"
REGISTER_FILE = "evidence_register.json"
EVIDENCE_ID = "EV-001"


def get_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def calculate_sha256(filename):
    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# ---------------------------------------------------------
# STEP 1: Create a test evidence file
# ---------------------------------------------------------

if not os.path.exists(EVIDENCE_FILE):

    with open(EVIDENCE_FILE, "w") as file:
        file.write("Digital Forensics Evidence Sample\n")
        file.write("This file is used for SHA-256 verification.\n")

    print("Test evidence file created:", EVIDENCE_FILE)


# ---------------------------------------------------------
# STEP 2: Create original evidence register
# ---------------------------------------------------------

if not os.path.exists(REGISTER_FILE):

    original_hash = calculate_sha256(EVIDENCE_FILE)

    register = {
        "evidence_id": EVIDENCE_ID,
        "file_name": EVIDENCE_FILE,
        "acquisition_time": get_time(),
        "original_hash": original_hash
    }

    with open(REGISTER_FILE, "w") as file:
        json.dump(register, file, indent=4)

    print("Evidence register created:", REGISTER_FILE)


# ---------------------------------------------------------
# STEP 3: Read evidence register
# ---------------------------------------------------------

with open(REGISTER_FILE, "r") as file:
    register = json.load(file)


original_hash = register["original_hash"]
acquisition_time = register["acquisition_time"]


# ---------------------------------------------------------
# STEP 4: Calculate current SHA-256 hash
# ---------------------------------------------------------

verification_time = get_time()

current_hash = calculate_sha256(EVIDENCE_FILE)


# ---------------------------------------------------------
# STEP 5: Compare hashes
# ---------------------------------------------------------

if original_hash.lower() == current_hash.lower():
    status = "VERIFIED - Evidence integrity maintained"
else:
    status = "WARNING - Evidence potentially altered"


# ---------------------------------------------------------
# STEP 6: Display chain-of-custody record
# ---------------------------------------------------------

print("\n")
print("=" * 60)
print("       DIGITAL EVIDENCE CHAIN OF CUSTODY")
print("=" * 60)

print("Evidence ID       :", EVIDENCE_ID)
print("File Name         :", EVIDENCE_FILE)
print("Acquisition Time  :", acquisition_time)
print("Original SHA-256  :", original_hash)
print("Verification Time :", verification_time)
print("Current SHA-256   :", current_hash)

print("-" * 60)
print("STATUS            :", status)
print("=" * 60)


# ---------------------------------------------------------
# STEP 7: Forensic interpretation
# ---------------------------------------------------------

print("\nFORENSIC INTERPRETATION")
print("-" * 60)

if original_hash.lower() == current_hash.lower():

    print("OBSERVED FACT:")
    print("The original SHA-256 and current SHA-256 values match.")

    print("\nINTERPRETATION:")
    print("No change to the file contents was detected during")
    print("this verification.")

else:

    print("OBSERVED FACT:")
    print("The original SHA-256 and current SHA-256 values differ.")

    print("\nINTERPRETATION:")
    print("The evidence file is potentially altered.")
    print("Further forensic examination is required.")

print("-" * 60)
