import re

file_path = r'C:\Users\Martin\Desktop\escaner\backend\core\scanner.py'
with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
in_class = False

for line in lines:
    if line.startswith('class ScannerEngine:'):
        in_class = True
        new_lines.append(line)
        continue
        
    if in_class and line.startswith('if __name__ =='):
        in_class = False
        
    if in_class:
        # replace print( with self._log( but preserving indentation
        new_line = re.sub(r'(\s+)print\(', r'\1self._log(', line)
        new_lines.append(new_line)
    else:
        new_lines.append(line)

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
