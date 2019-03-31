extrn MessageBoxA: PROC ; external functions in system libraries

_DATA	SEGMENT
caption db '64-bit hello!', 0
message db 'Hello World!', 0
_DATA ENDS

_TEXT	SEGMENT

CallMSG PROC
  sub    rsp,28h      ; shadow space, aligns stack
  mov    rcx, 0       ; hWnd = HWND_DESKTOP
  lea    rdx, message ; LPCSTR lpText
  lea    r8,  caption ; LPCSTR lpCaption
  mov    r9d, 0       ; uType = MB_OK
  call   MessageBoxA  ; call MessageBox API function
  ret 8
CallMSG ENDP

_TEXT	ENDS
End