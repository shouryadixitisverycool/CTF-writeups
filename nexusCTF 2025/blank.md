## Challenge Overview
**Category:** Reverse  
**Difficulty:** Easy  
**Tools Used:** Ghidra  
### Challenge Description
>Why should we trust the kernel mode Syscalls to handle the errors ?
### Files
[blank](https://github.com/shouryadixitisverycool/CTF-writeups/blob/main/nexusCTF%202025/files/blank)
## My Solution
Decompiling the file using Ghidra, we see this
```c
undefined8 main(void)
{  
	size_t arrlen;  
	long offset;  
	int i;  
	int j;  
	byte arr [40];  
	long local_10;
	
	local_10 = *(long *)(offset + 40);  
	for (i = 0; i < NUM_SEGMENTS; i = i + 1)
	{  
		for (j = 0; j < 32; j = j + 1)
		{  
			arr[j] = cipher_segments[(long)i * 32 + (long)j] ^ pads[(long)i * 32 + (long)j];  
		}  
		arrlen = strlen((char *)arr);  
		write(5,arr,arrlen);  
		read(7,arr,1);  
		write(8,&DAT_0047f010,2);  
	}  
	if (local_10 != *(long)(offset + 40))
	{  
		/* WARNING: Subroutine does not return */  
		__stack_chk_fail();  
	}  
	return 0;  
}
```

This code is decrypting the flag in chunks
- It iterates through `NUM_SEGMENTS` times.
- Each iteration, it XORs `cipher_segments` with `pads` to create a plaintext string in `arr`.
- `write(5, arr, arrlen)` tries to write the decrypted flag into File Descriptor (FD) 5.
- `read(7, arr, 1)` tries to read a synchronisation byte from FD 7.
- `write(8, &DAT_0047f010, 2)` writes status data to FD 8.

But in a standard linux shell, only 3 FDs are open by default:
- `0` stdin
- `1` stdout
- `2` stderr

This is why when we run this file, nothing happens. It tries to write to FD 5 but it is closed and the kernel returns an error `EBADF` (Bad file descriptor). This is what the challenge description is also talking about. It's hinting that the data was still passed to syscalls even though the FD was closed.

running this command
```bash
strace -s 100 -e write ./blank
```
here
- `-s 100` increases string size limit to 100
- `-e write` only prints `write` calls
gives this output
```bash
write(5, "nexus{", 6)                   = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
write(5, "th3_f", 5)                    = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
write(5, "l4g_w1ll", 8)                 = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
write(5, "_r3ve4l", 7)                  = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
write(5, "_1ts3l", 6)                   = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
write(5, "f_wh3n", 6)                   = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
write(5, "_y0u_", 5)                    = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
write(5, "st0p_", 5)                    = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
write(5, "look", 4)                     = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
write(5, "1ng}", 4)                     = -1 EBADF (Bad file descriptor)
write(8, "OK", 2)                       = -1 EBADF (Bad file descriptor)
```

Ignoring the `OK`, we have our flag
```perl
nexus{th3_fl4g_w1ll_r3ve4l_1ts3lf_wh3n_y0u_st0p_look1ng}
```
