%define arg_0	bp+4
%define arg_1	bp+8
%define arg_2	bp+12


org 100h

; ====================================================================
start:
	
	mov 	ax, cs
	mov		ds, ax
	mov 	es, ax

	mov 	si, start_str
	call	print_str_si
	
	call	print_password

	call	get_part1

;	mov 	ax,4c00h
;	int 	21h
	
	mov	si, boot_str
	call print_str_si
	mov ah, 0
	int 16h
		
	push 09000h
	push 04a9ch
	retf

start_str 	db "Starting the xxxx ...", 0dh, 0ah, 00
boot_str	db 0dh, 0ah, "Now booting the windows ... (press any key)", 0dh, 0ah, 0
; ====================================================================

; --------------------------------------------------------------------
; print_char_ax
; output char at cursor, and advance cursor
; input: byte to print in ax
print_char_ax:
	mov     bx, 7
	mov     ah, 0Eh
	int     10h 
	
	retn
	

; --------------------------------------------------------------------
; print_hex_byte_ax
; output hex byte at cursor, and advance cursor
; input: byte to print in ax
print_hex_byte_ax:	
	mov 	bx, ax
	push 	bx
	
	and		bx, 0f0h
	shr		bx, 4
	mov		ax, [hex_tbl+bx]
	call	print_char_ax
	
	pop 	bx
	and 	bx, 0fh
	mov		ax, [hex_tbl+bx]
	call 	print_char_ax
	
	retn
hex_tbl db '0123456789abcdef'
	
	
; --------------------------------------------------------------------
get_part1:

	; read mbr into buffer
	;
	; INT 13 - DISK - READ SECTOR(S) INTO MEMORY
	; AH = 02h
	; AL = number of sectors to read (must be nonzero)
	; CH = low eight bits of cylinder number
	; CL = sector number 1-63 (bits 0-5)
	;      high two bits of cylinder (bits 6-7, hard disk only)
	; DH = head number
	; DL = drive number (bit 7 set for hard disk)
	; ES:BX -> data buffer	
	mov 	ax, 0201h
	mov		bx, buffer
	mov		cx, 1
	mov		dx, 080h
	int 	13h
	
	call	print_buffer

	retn
		
	; get part 1
	call	print_newline
	mov		si, p_chs_start_str_h
	call	print_str_si
	mov		al, [buffer + 01ceh + 1] ; h
;	mov		[p1_chs_start_h], al
	call 	print_hex_byte_ax
	call	print_newline

	mov		si, p_chs_start_str_s
	call	print_str_si
	mov		al, [buffer + 01ceh + 2] ; s
;	mov		[p1_chs_start_s], al
	call 	print_hex_byte_ax
	call	print_newline
	
	mov		si, p_chs_start_str_c
	call	print_str_si
	mov		al, [buffer + 01ceh + 3] ; c
;	mov		[p1_chs_start_c], al
	call 	print_hex_byte_ax
	call	print_newline
	
	mov		al, [buffer + 01ceh + 1]  
	mov 	dh, al
	mov		al, [buffer + 01ceh + 2]  
	mov		cl, al
	mov		al, [buffer + 01ceh + 3]  
	mov		ch, al

	mov		dl, 080h
	mov 	ax, 0201h
	mov 	bx, buffer
	int 	13h
	jc		print_error
	
	mov		si, p_msg
	call	print_str_si

	call	print_buffer

	retn

p_chs_start_str_c db "Partition start c: ", 0
p_chs_start_str_h db "Partition start h: ", 0
p_chs_start_str_s db "Partition start s: ", 0
p1_chs_start_c	db 0
p1_chs_start_h	db 0
p1_chs_start_s	db 0

p_msg db "Partition 1 BR: ", 0dh , 0ah, 0 

print_error:
	push 	ax
	mov 	si, errmsg
	call	print_str_si
	pop 	ax
	call	print_hex_byte_ax
	retn

errmsg	db "ERROR: AH=", 0

; --------------------------------------------------------------------
print_str_si:
	lodsb
	or 		al,al
	jz 		.end_print
	
	mov     bx, 7
	mov     ah, 0Eh
	int     10h 
	jmp 	print_str_si
	
.end_print:
	retn

; --------------------------------------------------------------------
print_password:
	mov 	si, password_str
	call	print_str_si
	
	mov		ax, 09000h
	mov		ds, ax
	
	mov		si, 026h
	call	print_str_si
	
	mov		ax, cs
	mov		ds, ax
	retn
	
password_str db "Your password is: " , 0	
	
; --------------------------------------------------------------------
print_newline:
	mov 	si, CR_LF
	call 	print_str_si
	retn
CR_LF db 0dh, 0ah, 0
	
; --------------------------------------------------------------------
print_buffer:
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
	call 	print_char_ax
	mov 	ax, 0ah
	call 	print_char_ax

	pop 	cx
	push	cx
	mov		ax, 0200h
	sub		ax, cx
	shr		ax, 8
	call	print_hex_byte_ax
	pop 	cx
	push	cx
	mov		ax, 0200h
	sub		ax, cx
	call	print_hex_byte_ax
	mov		ax, ':'
	call	print_char_ax
	mov 	ax, ' '
	call	print_char_ax

	pop 	cx
	pop 	bx
	push 	bx
	push	cx
	
.no_newline:
	mov 	ax, [buffer+bx]
	call	print_hex_byte_ax
	mov		ax, ' '
	call 	print_char_ax
	pop 	cx
	pop		bx
	
	inc		bx
	loop	.loop1
	
	retn
					  
; ------------------------------------------------------------------
					  
buffer resb 512
