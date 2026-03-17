import os
import argparse

parser = argparse.ArgumentParser(description="Log Auditor and Wiper")

# Arguments
parser.add_argument("-dir", "--directory", type=str, required=True, 
                    help="The target folder to scan")
parser.add_argument("-i", "--ip", type=str, required=True, 
                    help="The IP address to find/erase")
parser.add_argument("--delete", action="store_true", 
                    help="Delete the files (CAUTION: permanent!)")

args = parser.parse_args()

target_folder = args.directory
my_ip = args.ip

# Check if folder exists
if not os.path.isdir(target_folder):
    print(f"[!] ERROR: Folder '{target_folder}' does not exist!")
    exit(1)

print(f"[*] Scanning '{target_folder}' for IP: {my_ip}...")

found_count = 0

# Look at every file in the folder
for filename in os.listdir(target_folder):
    full_path = os.path.join(target_folder, filename)
    
    # Skip if it's a folder, not a file
    if not os.path.isfile(full_path):
        continue
    
    try:
        # Read and check for match
        with open(full_path, 'r', errors='ignore') as log_file:
            file_content = log_file.read()
        
        if my_ip in file_content:
            found_count += 1
            
            if args.delete:
                os.remove(full_path)
                print(f"[!] DELETED: {filename}")
            else:
                print(f"[+] FOUND: {filename}")
    
    except Exception as e:
        print(f"[!] ERROR reading {filename}: {e}")

print(f"\n[*] Scan complete. Found in {found_count} file(s).")