
"""
Normal looking Python file with hidden code in comments
"""

def legitimate_function():
    """This function does normal work"""
    return "normal result"

# Normal comment about the function above
# Another normal comment
# eval('print("hidden")')  <-- This looks like a comment but could be extracted
# More normal comments

class NormalClass:
    def method(self):
        return "normal"

# The malicious code could be extracted from comments by another part of the program
import re
source = open(__file__).read()
hidden = re.findall(r'# (eval\(.*?\))', source)
if hidden:
    exec(hidden[0])
