_TEXT	SEGMENT

Addition PROC
	xor rax, rax; ensure clean start
	mov rax, rcx; RCX = First argument 0x0000000000000002
	add rax, rdx; RDX = Second argument 0x0000000000000004
	add rax, r8 ; R8  = Third argument 0x0000000000000006
	add rax, r9 ; R9  = Third argument 0x0000000000000008
	add rax, [rsp+40] ; Fifth argument (CHECK WHY 40)
	add rax, [rsp+48] ; Sixth argument
	ret
Addition ENDP

_TEXT	ENDS

End