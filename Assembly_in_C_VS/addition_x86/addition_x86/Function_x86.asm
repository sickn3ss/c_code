.model flat, c

_TEXT	SEGMENT

Addition PROC, Argument1:DWORD, Argument2:DWORD 
	xor eax, eax ; 0 out EAX
	mov eax, Argument1 ; Move first argument in EAX
	add eax, Argument2 ; Addition
	ret
Addition ENDP
_TEXT	ENDS

End