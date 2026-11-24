#!/usr/bin/env python3
import re
import sys
from pathlib import Path

def remove_comments_and_docstrings(content):
    lines = content.split('\n')
    result = []
    in_triple_quote = False
    triple_quote_char = None
    skip_next_empty = False
    
    for line in lines:
        stripped = line.strip()
        
        if '"""' in line or "'''" in line:
            if not in_triple_quote:
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    in_triple_quote = True
                    triple_quote_char = '"""' if '"""' in line else "'''"
                    if line.count(triple_quote_char) >= 2:
                        in_triple_quote = False
                    skip_next_empty = True
                    continue
                else:
                    cleaned = re.sub(r'#.*$', '', line).rstrip()
                    if cleaned or not skip_next_empty:
                        result.append(cleaned)
                        skip_next_empty = False
            else:
                if triple_quote_char in line:
                    in_triple_quote = False
                    skip_next_empty = True
                continue
        elif in_triple_quote:
            continue
        elif stripped.startswith('#'):
            skip_next_empty = True
            continue
        else:
            cleaned = re.sub(r'#.*$', '', line).rstrip()
            if cleaned:
                result.append(cleaned)
                skip_next_empty = False
            elif not skip_next_empty:
                result.append('')
            else:
                skip_next_empty = False
    
    while result and not result[-1].strip():
        result.pop()
    
    return '\n'.join(result)

files = [
    "ml/baselines/nbe_baseline.py",
    "ml/baselines/__init__.py",
    "ml/confidence_calibration.py",
    "ml/dynamic_weights.py",
    "ml/dynamic_thresholds.py",
    "ml/train_baselines_and_calibration.py"
]

for filepath in files:
    path = Path(filepath)
    if path.exists():
        print(f"Processing {filepath}...")
        content = path.read_text(encoding='utf-8')
        cleaned = remove_comments_and_docstrings(content)
        path.write_text(cleaned, encoding='utf-8')
        print(f"  ✓ Cleaned")
    else:
        print(f"  ✗ Not found: {filepath}")

print("\nAll files processed!")
