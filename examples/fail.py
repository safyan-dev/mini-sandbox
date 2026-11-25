import sys

print("this line goes to stdout")
print("this line goes to stderr", file=sys.stderr)
sys.exit(7)
