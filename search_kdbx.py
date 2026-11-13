import mmap

filepath = 'dumps/exercice3.raw'
try:
    with open(filepath, 'rb') as f:
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        
        offset = 0
        count = 0
        while True:
            offset = mmapped_file.find(b'\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5', offset)
            if offset == -1:
                break
            
            print(f"KDBX Header found at offset: {hex(offset)}")
            count += 1
            offset += 8
            
        print(f"Total KDBX headers found: {count}")
        
except Exception as e:
    print(f"Error: {e}")
