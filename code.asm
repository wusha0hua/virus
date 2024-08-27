bits 64
section .text
global _start
_start:
call label
label:
push rcx
sub rcx, label
mov rdx,len
add rcx,msg 
int 0x80
mov rbx,1
mov rax,4
jmp jump
section .data
msg db `hello!\n`
len equ $ - msg
jump:
mov rbx,0
mov rax,1
jmp near 0
