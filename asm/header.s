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

%define OPEN_DIR_PERMISSION 65536

%define sys_read 0
%define sys_write 1
%define sys_open 2
%define sys_close 3
%define sys_fstat 5
%define sys_mmap 9
%define sys_munmap 11
%define sys_getdents 78
%define sys_ptrace 101

%define padding db 0x90

%define DIRENT_SIZE 1024
struc	linux_dirent
	.d_ino:			resq	1	; 64-bit inode number
	.d_off:			resq	1	; 64-bit offset to next structure
	.d_reclen		resw	1	; Size of this dirent
	.d_name			resb	256	; Filename (null-terminated)
endstruc