import os

target_folder = r"C:\Program Files (x86)" # Change to target folder

keywords = [
    # Files
    "pass", "cred", "key", "token", "secret", "config", 
    "env", "db", "sql", "ssh", "rsa", "jwt", "api", 
    "auth", "login", "flag", "ctf",
    
    #Folders
    "admin", "backup", "private", "hidden", "log", "tmp",
    "install", "data", "users", "src", "git", "ssl",
    "cert", "archive", "old", "dev", "test", "staging"
]

for item_name in os.listdir(target_folder):
    full_path = os.path.join(target_folder, item_name)
    
    # Lowercase for reliable matching
    lower_name = item_name.lower()
    
    # Check for keyword matches
    for word in keywords:
        if word in lower_name:
            if os.path.isdir(full_path):
                item_type = "[DIR] "
            else:
                item_type = "[FILE]"
                
            print(f"Match {item_type}: {item_name} ({full_path})")
            break