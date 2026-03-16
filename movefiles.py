import os

#folder we want to wipe logs
target_folder = r"B:\Scripts\target_logs" 

#to erase
my_ip = "192.168.1.50"

# 3. Look at every file in the folde
for filename in os.listdir(target_folder):
    full_path = os.path.join(target_folder, filename)
    
    #Read file and check ip match 
    with open(full_path, 'r') as log_file:
        file_content = log_file.read()
        
    # if match found , destroy file.
    if my_ip in file_content:
        
       
        print(f"[!] Target IP found! Wiping file: {filename}")
        
        # os.unlink(full_path)