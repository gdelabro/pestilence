%include "asm/header.s"

section .text
global _start

_start:
	PUSHAQ
	mov rbp, rsp
	jmp main

strlen:
	enter 0, 0
	push rcx
	mov rax, 0
	mov rsi, rdi
	strlen_while:
		mov al, byte [rsi]
		cmp rax, 0
		je strlen_end_while
		inc rsi
		jmp strlen_while
	strlen_end_while:
	sub rsi, rdi
	mov rax, rsi
	pop rcx
	leave
	ret

process_dir:
	enter 0, 0
	sub rsp, DIRENT_SIZE + NAME_SIZE
	mov rax, sys_open
	mov rdi, rdi
	mov rsi, OPEN_DIR_PERMISSION
	xor rdx, rdx
	syscall							; it opens the dir
	padding
	mov r12, rax
	cmp rax, 0
	jl end_process_dir
	run_through_files:
		mov rdi, r12
		lea rsi, [rsp]
		mov rdx, DIRENT_SIZE
		mov rax, sys_getdents
		syscall						; it reads dir
		padding

		cmp rax, 0
		jle close_dir
		mov r9, rax
		add r9, rsp
		mov rcx, rsp
		file_listing:
			lea rdi, [rcx + linux_dirent.d_name]
			call strlen

			xor rdi, rdi
			lea rsi, [rcx + linux_dirent.d_name]
			mov rdx, rax
			mov rax, sys_write
			push rcx
			syscall
			padding
			pop rcx
			print_nl

			xor r8, r8
			mov r8w, WORD [rcx + linux_dirent.d_reclen]
			add rcx, r8
			cmp rcx, r9
			jge end_file_listing
			jmp file_listing
		end_file_listing:
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
		xor rdi, rdi
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
new_line:
	db 0x0a, 0
end: