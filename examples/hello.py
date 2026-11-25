import os
import platform
import sys

print("hello from a sandbox")
print("kernel:", platform.release())
print("python:", sys.version.split()[0])
print("uid:", os.getuid())
print("cwd:", os.getcwd())
