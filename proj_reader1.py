import re
import pyperclip

# find standard IP addresses
ip_reader = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

# Grab text
ip_messy = str(pyperclip.paste())

# Scan text and pull every IP it finds
ip_matches = ip_reader.findall(ip_messy)

# Put each IP on a new line
ip_clean = "\n".join(ip_matches)

# Copy the clean list
pyperclip.copy(ip_clean)

# Print to the terminal
print("Found IPs are:\n" + str(ip_clean))
print("Number of IPs Found: " + str(len(ip_matches)))