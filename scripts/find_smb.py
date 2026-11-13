import sys
import os

pattern = b"\xffSMB"
filename = "dumps/exercice4.raw"

if not os.path.exists(filename):
    print(f"File not found: {filename}")
    sys.exit(1)

size = os.path.getsize(filename)
print(f"File size: {size}")

with open(filename, "rb") as f:
    data = f.read()
    print(f"Read {len(data)} bytes")
    offset = 0
    count = 0
    while True:
        offset = data.find(pattern, offset)
        if offset == -1:
            break
        if offset + 4 < len(data):
            cmd = data[offset+4]
            print(f"Found SMB at offset: {offset}, Command: {hex(cmd)}")
        offset += 1
        count += 1
        if count > 1000:
            break
