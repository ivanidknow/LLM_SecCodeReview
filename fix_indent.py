import sys

file_path = r"C:\Users\user\Desktop\security review\backend\app\api\analysis.py"

with open(file_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

for i in range(942, 1044):
    if lines[i].strip():
        lines[i] = "    " + lines[i]

with open(file_path, "w", encoding="utf-8") as f:
    f.writelines(lines)
print("Indentation fixed.")
