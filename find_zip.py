import sys

try:
    with open('extractions/galf.jpeg', 'rb') as f:
        data = f.read()
    
    zip_idx = data.find(b'PK\x03\x04')
    if zip_idx != -1:
        print(f"ZIP found at index: {zip_idx}")
    else:
        print("No ZIP found")
        
    rar_idx = data.find(b'Rar!\x1a\x07\x00')
    if rar_idx != -1:
        print(f"RAR found at index: {rar_idx}")
    else:
        print("No RAR found")
        
    sz_idx = data.find(b'7z\xbc\xaf\x27\x1c')
    if sz_idx != -1:
        print(f"7z found at index: {sz_idx}")
    else:
        print("No 7z found")
except Exception as e:
    print(f"Error: {e}")
