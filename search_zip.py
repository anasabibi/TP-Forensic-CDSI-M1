import mmap
import os

filepath = 'dumps/exercice3.raw'
try:
    with open(filepath, 'rb') as f:
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        
        offset = 0
        while True:
            offset = mmapped_file.find(b'PK\x03\x04', offset)
            if offset == -1:
                break
            
            print(f"ZIP Header found at offset: {hex(offset)}")
            try:
                name_len = int.from_bytes(mmapped_file[offset+26:offset+28], byteorder='little')
                if 0 < name_len < 100:
                    filename = mmapped_file[offset+30:offset+30+name_len].decode('ascii', errors='ignore')
                    print(f"  -> Contains file: {filename}")
            except Exception as e:
                print(f"  -> Error reading filename: {e}")
                
            offset += 4
            
except Exception as e:
    print(f"Error: {e}")
