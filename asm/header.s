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

%define OPEN_DIR_PERMISSION		65536
%define OPEN_PROC_PERMISSION	0
%define MMAP_PROT				3
%define MAP_PRIVATE				2
%define OPEN_FILE_PERMISSION	0

%define sys_read 0
%define sys_write 1
%define sys_open 2
%define sys_close 3
%define sys_lstat 6
%define sys_mmap 9
%define sys_munmap 11
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

%define ELF_STRUC_SIZE 1024
struc elf_struc
	.stat			resb	STAT_STRUC_SIZE
	.path			resq	1
	.fd				resd	1
	.ptr			resq	1
endstruc