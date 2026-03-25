## Challenge Overview
**Category:** Reverse  
**Difficulty:** Easy-Mid  
**Tools Used:** Ghidra, python  
### Challenge Description
>My Grecian girlfriend sent me a C file. She knows I love this stuff. But the file seems broken... or is it?
### Files
[apeiros](https://github.com/shouryadixitisverycool/CTF-writeups/blob/main/nexusCTF%202025/files/apeiros.c)
## My Solution
When you open the file, you'll realise all the code is obfuscated by defining each individual component separately as shown
```c
#define zzzz_zzzzzzzzz main
#define zzzzzzzzz_zzzzzzzzzzzzzz 's'
#define zzzzzzzzzzzzz 'p'
#define zzzzzzzz_zzzzzzzzzzzzzzzzzzz 'r'
#define zz_zzzz 16
#define zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz 'x'
#define zzzzzzzzzz_zzzzzzzzzzzzz 4
#define zzzzzz_zzzzzzzzzzzzzzzzzzzzzzzzz '\0'
#define zzzz_zzzzzzzzzzzzzzzzzzzzz 19
#define zzzzzzz_zzzz '0'
#define zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz 50
#define z_zzz '_'
#define zzzzzzzzzzzzzzzzzzzzzzzzzz 'n'
#define z_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz '4'
#define zzz_zzzzzzzzz 36
#define zzzzz_zzzzzzzzzzzz 'e'
#define zzzzzzzzzzzzzzzzzzzzzzzz 't'
#define zzz_zzzzzzzzzzzzzzzz 7
#define zzzzzzzzzzz_zzzzz '1'
#define z_z 0
#define zzzzzzzzzzzzzzzzzzzzzzzzzzzz '}' 
```
It also has a lot of zero-width characters like `\u200b`.  
To remove all these characters and replace the macros back to normal, i wrote this python script
```python
#!/usr/bin/env python3
import re

# Read the file
with open('apeiros.c', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Remove all zero-width characters and fix lookalike characters
zero_width = [
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\ufeff',  # BOM
]
for zw in zero_width:
    content = content.replace(zw, '')

# Replace Greek question mark (looks like semicolon) with actual semicolon
content = content.replace('\u037E', ';')  # Greek question mark
content = content.replace('；', ';')  # Fullwidth semicolon

# Parse the #defines
defines = {}
lines = content.split('\n')

for line in lines:
    line = line.strip()
    if line.startswith('#define '):
        parts = line[8:].split(' ', 1)
        if len(parts) == 2:
            macro_name = parts[0].strip()
            value = parts[1].strip()
            defines[macro_name] = value

# Get the code part (after includes and defines)
code_start = content.find('zzzz_zz zzzz_zzzzzzzzz(')
if code_start == -1:
    code_start = content.find('int main')
    
code = content[code_start:] if code_start != -1 else content

# Sort defines by length (longest first) to avoid partial replacements
sorted_defines = sorted(defines.items(), key=lambda x: len(x[0]), reverse=True)

# Replace all macros with their values
for macro_name, value in sorted_defines:
    code = code.replace(macro_name, value)

# Fix invalid C identifiers that start with numbers
# Map them to valid names
invalid_identifiers = {
    '26zZZ': 'format_str',
    '1_ZZZ_zZZZ': 'state',
    '1_ZZZ_ZzZZ': 'is_valid',
}

for invalid, valid in invalid_identifiers.items():
    code = code.replace(invalid, valid)

# Fix the typo: z_state should be state (or whatever 1_ZZZ_zZZZ was mapped to)
code = code.replace('z_state', 'state')

# Clean up obfuscated variable names with Z's
obfuscated_vars = {
    'zzz_ZZZZ': 'correct_msg',
    'zzz_ZzZ': 'prompt_msg',
    'mainz': 'fake_flag',
}

for obfuscated, clean in obfuscated_vars.items():
    code = code.replace(obfuscated, clean)

# Clean up the single letter 'Z' variable (index counter)
# Be careful not to replace Z in other contexts
code = re.sub(r'\bZ\b', 'index', code)

# Clean up multiple spaces and excessive newlines
code = re.sub(r' +', ' ', code)
code = re.sub(r'\n{3,}', '\n\n', code)

# Format the switch cases better for readability
code = re.sub(r'break;case', 'break;\n case', code)
code = re.sub(r'(\d+) :', r'\1:', code)

# Fix character array syntax errors (bare numbers should be in quotes)
# Look for patterns like: 'x', 8, 'y' and replace with 'x', '8', 'y'
code = re.sub(r"(,\s*)(\d+)(\s*,)", r"\1'\2'\3", code)

# Add the missing #include at the beginning if not present
if '#include' not in code:
    code = '#include <stdio.h>\n' + code

# Save the full output
with open('decrypted_complete.c', 'w') as f:
	f.write(code)
```
This gives us the cleaned C file
```c
#include <stdio.h>
int main() {
 char z[50];
 char fake_flag[] = {
 'n', 'e', 'x',
 'u', 's', '{',
 'c', '0', 'm', '1',
 'n', '8', 'e', '?',
 '_', 'n', '4', 'h',
 '_', 'k', '3', '3', 'p', '_',
 's', '3', '4',
 'c', 'h', '}', '\0'
 };
 char correct_msg[] = {
 'c', 'o', 'r',
 'r', 'e', 'c',
 't', '\n', '\0'
 };
 char prompt_msg[] = {
 'E', 'n', 't',
 'e', 'r', ' ', 'f',
 'l', 'a', 'g',
 ':', ' ', '\0'
 };
 char format_str[] = {
 '%', 's', '\0'
 };
 printf(format_str, prompt_msg);
 scanf(format_str, z);
 int state = 1337;
 int index = 0;
 int is_valid = 1;
 while(state != 101) {
 switch(state) {
 case 8008:
 if(z[index++] != '4') state = 666; if(z[index++] != 'r') state = 666; if(z[index++] != '3') state = 666; if(z[index++] != '_') state = 666;if(z[index++] != 'u') state = 666;if(z[index++] != 'n') state = 666;if(z[index++] != 'd') state = 666;if(z[index++] != '3') state = 666;if(z[index++] != 'r') state = 666;if(state != 666) state = 555;break;
 case 1337:if(z[index++] != 'n') state = 666;if(z[index++] != 'e') state = 666;if(z[index++] != 'x') state = 666;if(z[index++] != 'u') state = 666;if(z[index++] != 's') state = 666;if(z[index++] != '{') state = 666;if(state != 666) state = 404;break;
 case 90210:if(z[index++] != '3') state = 666;if(z[index++] != 's') state = 666;if(z[index++] != 's') state = 666;if(z[index++] != '0') state = 666;if(z[index++] != 'r') state = 666;if(z[index++] != '_') state = 666;if(state != 666) state = 8008;break;
 case 555:if(z[index++] != '3') state = 666;if(z[index++] != 's') state = 666;if(z[index++] != 't') state = 666;if(z[index++] != '1') state = 666;if(z[index++] != 'm') state = 666;if(z[index++] != '4') state = 666;if(z[index++] != 't') state = 666;if(z[index++] != '3') state = 666;if(z[index++] != 'd') state = 666;if(z[index++] != '}') state = 666;if(state != 666) state = 101;break;
 case 404:if(z[index++] != 'p') state = 666;if(z[index++] != 'r') state = 666;if(z[index++] != '3') state = 666;if(z[index++] != 'p') state = 666;if(z[index++] != 'r') state = 666;if(z[index++] != '0') state = 666;if(z[index++] != 'c') state = 666;if(state != 666) state = 90210;break;
 case 666:
 is_valid = 0;
 state = 101;
 break;
 default:
 state = 666;
 break;
 }
 }
 if(is_valid == 1) {
 printf(format_str, correct_msg);
 return 1;
 } else{
 return 0;
 }
}
```
The program seems to be using some sort of state machine which starts at `1337` and cycles through the states to check the flag char by char.  
Tracking the `if` statement checks, we can build the flag one by one.  
The state cycle goes as follows: 1337 $\to$ 404 $\to$ 90210 $\to$ 8008 $\to$ 555 $\to$ 666 (end)  
1337 $\to$ `nexus{`  
404 $\to$ `pr3pr0c`  
90210 $\to$ `3ss0r_`  
8008 $\to$ `4r3_und3r`  
555$\to$ `3st1m4t3d}`  
### Final flag
```perl
nexus{pr3pr0c3ss0r_4r3_und3r3st1m4t3d}
```
