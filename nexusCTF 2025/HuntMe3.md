## Challenge Overview
**Category:** Reverse  
**Difficulty:** Medium  
**Tools Used:** Ghidra, python  
### Challenge Description
> The forest is no longer just watched. 
> Now, every step you take is measured.  
> Every wrong move is quietly absorbed by the trees.  
> Only those who truly understand the pattern may pass.
### Files
[HuntMe3](https://github.com/shouryadixitisverycool/CTF-writeups/blob/main/nexusCTF%202025/files/HuntMe3)
## My Solution
Opening the file in Ghidra we see a lot of encryption functions, but some of these are red herrings.
```c
undefined8 main(void)
{  
	int enc3input;  
	char *pointerToInput;  
	undefined8 uVar1;  
	char input [264];  
	char *i;
	
	puts(&DAT_00402110);  
	puts(" THE FINAL HUNT - Where Shadows Meet Light ");  
	puts(&DAT_00402110);  
	puts("");  
	puts("The forest stands silent, waiting.");  
	puts("You have tracked through two trials, mastered two paths.");  
	puts(&DAT_00402278);  
	puts("");  
	puts("Three hunts complete the cycle.");  
	puts("Three patterns woven into one.");  
	puts("Only those who see beyond the surface may pass.");  
	puts("");  
	puts("The trees lean close, listening for your answer...");  
	puts("");  
	printf(&DAT_0040235b);  
	fileflush(stdout);  
	pointerToInput = fgets(input,256,stdin);  
	if (pointerToInput == (char *)0)
	{  
		puts(&DAT_00402360);  
		uVar1 = 1;  
	}  
	else
	{  
		for (i = input; *i != '\0'; i = i + 1)
		{  
			if ((*i == '\n') || (*i == '\r'))
			{  
				*i = '\0';  
				break;  
			}  
		}  
		enc3input = enc3(input);  
		if (enc3input == 0)
		{  
			puts("");  
			puts(&DAT_00402508);  
			puts(" The patterns remain hidden.");  
			puts(" The hunt continues...");  
			puts("");  
		}  
		else
		{  
			puts("");  
			puts(" THE FOREST RECOGNIZES ITS MASTER ");  
			puts("");  
			puts("The trees part before you.");  
			puts("Light breaks through the canopy.");  
			puts(&DAT_00402420);  
			puts("You are the one who understands.");  
			puts("");  
			puts("Three trials conquered. Three secrets revealed.");  
			puts("The forest grants you passage eternal.");  
			puts("");  
			puts(" CONGRATULATIONS, MASTER HUNTER ");  
			puts("");  
		}  
		uVar1 = 0;  
	}  
	return uVar1;  
}
```
The code takes our input and puts it through `enc3()` which if it returns `non-zero`, then we have our answer.  
Looking inside `enc3()`
```c
undefined8 enc3(char *funcInput)
{  
	byte bVar1;  
	size_t strlength;  
	undefined8 uVar2;  
	int i;
	
	strlength = strlen(funcInput);  
	if (strlength == 53)
	{  
		enc1();  
		enc2();  
		for (i = 0; i < 53; i = i + 1)
		{  
			bVar1 = enc4(i);  
			if ((byte)(funcInput[(byte)(&DAT_00402040)[i]] ^ bVar1) != (&DAT_00402080)[i])
			{  
				if ((((uint)(byte)(funcInput[(byte)(&DAT_00402040)[i]] ^ bVar1) ^ i * 0x11) & 1) != 0)
				{  
					return 0;  
				}  
				return 0;  
			}  
		}  
		uVar2 = 1;  
	}  
	else
	{  
		uVar2 = 0;  
	}  
	return uVar2;  
}
```
We see 3 new functions `enc1()`, `enc2()`, and `enc4()` here. But if you open `enc1()` and `enc2()`, you'll realise they require an input and give a return value which means just calling them like this wont have any effect on our code.  
Now, the second thing to notice here is that the length of our input/flag must be 53 characters long.  
From the `if` statements we see that `funcInput[arr1[i]] ^ enc4(i) == arr2[i]` and `funcInput[arr1[i]] ^ enc4(i) ^ (i*17)` must be odd.  
Looking at `enc4()`
```c
uint enc4(int x)
{  
	uint uVar1;  
	undefined4 i;  
	undefined4 c;  
	undefined4 b;  
	undefined4 a;
	
	a = 0x7a8ab05c;  
	b = 0x362d12d2;  
	c = 0x1574b128;  
	for (i = 0; (int)i <= x; i = i + 1)
	{  
		a = a + 0xe868d9fc;  
		b = b + i * i;  
		c = enc5(c,i & 7);  
	}  
	uVar1 = a ^ b ^ c >> ((byte)x & 7);  
	uVar1 = uVar1 & 255 ^ (uVar1 & 31) << 3;  
	return uVar1 ^ uVar1 >> 5;  
}

uint enc5(uint a,byte b)
{  
	return a << (b & 31) | a >> 32 - (b & 31);  
}
```
It seems to generate a single-byte key which we XOR with `funcInput[arr1[i]]` to encrypt it where `arr1[]` seems to just shuffle our indices. This means `arr2[]` holds our encrypted bytes and we just need to decrypt it.  
We need to do `funcInput[arr[i]] = arr2[i] ^ enc4(i)`. Taking the values of these arrays using Ghidra, I wrote this python script to decrypt our flag.
```python
def verify_solution():
    # Permutation table from DAT_00402040
    p_table = [
        0x2d, 0x2c, 0x32, 0x14, 0x06, 0x25, 0x0f, 0x03, 0x22, 0x07, 0x2f, 0x23, 0x00, 0x31, 0x1c, 0x27, 
        0x10, 0x02, 0x30, 0x0a, 0x2a, 0x16, 0x05, 0x12, 0x1d, 0x01, 0x09, 0x17, 0x1b, 0x1f, 0x1a, 0x08, 
        0x0c, 0x24, 0x04, 0x20, 0x2e, 0x34, 0x0b, 0x26, 0x0e, 0x33, 0x15, 0x1e, 0x19, 0x29, 0x13, 0x11, 
        0x2b, 0x28, 0x21, 0x0d, 0x18
    ]
    
    # Target encrypted bytes from DAT_00402080
    targets = [
        0xc7, 0x8e, 0x0b, 0xe5, 0x23, 0x81, 0x18, 0x23, 0x27, 0xed, 0x06, 0xa1, 0x19, 0x30, 0x38, 0xd0, 
        0x2e, 0x66, 0xe2, 0x26, 0x6e, 0x23, 0xaa, 0xa1, 0x5d, 0x7d, 0x36, 0xe5, 0x6c, 0x6d, 0x35, 0xa0, 
        0x34, 0x0c, 0xf9, 0x84, 0xd7, 0xc9, 0x5e, 0x56, 0xc2, 0xe9, 0x44, 0xe0, 0x77, 0x7b, 0x20, 0x78, 
        0x1f, 0xd9, 0x98, 0x85, 0xf5
    ]
    
    def enc5(a, b):
        """Circular shift function"""
        b = b & 31
        return ((a << b) | (a >> (32 - b))) & 0xFFFFFFFF
    
    def enc4(x):
        """Key generator function"""
        local_c = 0x7a8ab05c
        local_10 = 0x362d12d2
        local_14 = 0x1574b128
        
        for i in range(x + 1):
            local_c = (local_c + 0xe868d9fc) & 0xFFFFFFFF
            local_10 = (local_10 + (i * i)) & 0xFFFFFFFF
            local_14 = enc5(local_14, i & 7)
        
        uVar1 = local_c ^ local_10 ^ (local_14 >> (x & 7))
        uVar1 = (uVar1 & 255) ^ ((uVar1 & 31) << 3)
        result = uVar1 ^ (uVar1 >> 5)
        return result & 0xFF
    
    # Decrypt the flag
    flag = ['?'] * 53
    
    for i in range(53):
        key = enc4(i)
        perm_idx = p_table[i]
        decrypted_byte = targets[i] ^ key
        decrypted_char = chr(decrypted_byte)
        flag[perm_idx] = decrypted_char

    final_flag = "".join(flag)
    
    print(final_flag)
    return final_flag
if __name__ == "__main__":
    verify_solution()

```
### Final flag
```perl
nexus{thr33_hunt5_c0mpl3t3_th3_f0r3st_gr4nts_p4ss4g3}
```
