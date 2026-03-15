import re
import pprint
text = """Welcome to the organizing committee for the Stranger's CTF! We need to verify all the contact details before Techtrix '26 kicks off. The main coordinator can be reached at +91 9876543210. 

For infrastructure issues during the event, call the tech lead at 8765432109. Please do not mix this up with the RCCIIT campus security shortcode, which is just 10023 or the date 26-03-2026. If the campus network goes down, immediately dial +91 1122334455. 

We also have two backup admins on standby for the bug bounty segment: you can call Mike at 9998887776 or Dustin at +91 5556667778. My personal number is still 7439766971 if there is a critical bug in the capture-the-flag challenges. Also, the vendor delivering the event hoodies gave us this contact: 1234567890. Let's make this tech fest massive!"""

check = re.compile(r"(?:\+\d\d )*\d{10}")
mo = check.findall(text)
pprint.pprint(mo)