# Test each import individually
try:
    import networkx
    print("networkx imported successfully")
except ImportError as e:
    print(f"Error importing networkx: {e}")

try:
    import matplotlib.pyplot as plt
    print("matplotlib imported successfully")
except ImportError as e:
    print(f"Error importing matplotlib: {e}")

try:
    import tkinter as tk
    print("tkinter imported successfully")
except ImportError as e:
    print(f"Error importing tkinter: {e}")

# Print Python environment info
import sys
print("\nPython version:", sys.version)
print("Python executable:", sys.executable)
print("Python path:", sys.path)

# Print installed packages
import pkg_resources
print("\nInstalled packages:")
for package in pkg_resources.working_set:
    print(f"{package.key} - Version: {package.version}")