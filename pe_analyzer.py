import struct
import os
import math
import datetime

def calculate_entropy(data):
    """Calculate Shannon Entropy (0.0 to 8.0) to detect packing/encryption."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def analyze_pe(file_path):
    file_path = file_path.strip('"\'')
    print(f"\n[*] Target File: {file_path}")
    print("-" * 60)
    
    if not os.path.exists(file_path):
        print("[!] Error: File not found! Please check the path.")
        return

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
            file_size = len(file_bytes)
            
            # 1. Verify MS-DOS Header
            f.seek(0)
            mz = f.read(2)
            if mz != b'MZ':
                print("[!] Result: Not a valid Windows PE binary (Missing 'MZ' header).")
                return
            print("[+] [DOS Header] Valid MS-DOS Signature ('MZ') detected.")
            
            # 2. Extract PE Header Offset (e_lfanew at 0x3C)
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            
            # 3. Verify PE Signature
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                print("[!] Result: Invalid PE Signature.")
                return
            print(f"[+] [PE Header] Valid Signature 'PE\\x00\\x00' at offset 0x{pe_offset:X}.")
            
            # 4. Parse COFF File Header (20 bytes after PE signature)
            coff_header = f.read(20)
            machine, num_sections, timestamp, _, _, opt_header_size, characteristics = struct.unpack("<HHIIIHH", coff_header)
            
            # Machine Type Lookup
            machine_type = "x64 (AMD64)" if machine == 0x8664 else ("x86 (32-bit)" if machine == 0x14c else f"Unknown (0x{machine:X})")
            compile_time = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            
            print(f"[+] [Architecture] {machine_type}")
            print(f"[+] [Sections Count] {num_sections} binary section(s)")
            print(f"[+] [Compile Timestamp] {compile_time}")
            print(f"[+] [File Size] {file_size} bytes ({file_size / 1024:.2f} KB)")
            
            # 5. Shannon Entropy Calculation
            entropy = calculate_entropy(file_bytes)
            print(f"[+] [Binary Entropy] {entropy:.2f} / 8.00")
            
            if entropy > 7.1:
                print("    [!] Obfuscation Alert: High entropy detected. Binary is likely PACKED or ENCRYPTED.")
            else:
                print("    [+] Status: Normal entropy range (Standard/Unpacked executable).")
                
            print("-" * 60)
            print("[*] Static Analysis Completed Successfully.")

    except Exception as e:
        print(f"[!] Analysis failed: {e}")

if __name__ == "__main__":
    print("-" * 60)
    print("Z1 CH3N - Windows PE Binary Static Analyzer")
    print("-" * 60)
    target = input("Enter path to EXE file (e.g., C:\\Windows\\notepad.exe): ")
    analyze_pe(target)