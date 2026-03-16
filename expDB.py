import webbrowser 
import pyperclip

#pull sw version
target_software = pyperclip.paste()

#pasting here to auto-search
webbrowser.open("https://www.exploit-db.com/search?text=" + target_software)