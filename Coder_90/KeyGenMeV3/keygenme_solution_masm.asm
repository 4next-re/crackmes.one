  include     \masm64\include64\masm64rt.inc
  includelib  \masm64\lib64\msvcrt.lib 

  strlen PROTO C :PTR BYTE
  scanf PROTO C :PTR BYTE, :VARARG
  
  .data
    
    input db 64 dup(0)
    sN db "%s",0
  .code

entry_point proc

    conout "Name: "
    mov rdx, offset input
    mov rcx, offset sN
    call scanf
    mov rcx, offset input
    call keygen

    conout "Key : ", hex$(rax), lf 
	
	waitkey cfm$("\n  Press any key ....\n")

    invoke ExitProcess, 0

    ret

entry_point endp


keygen proc               
                push    rsi
                sub     rsp, 20h
                mov     rsi, rcx
                call    strlen
                movzx   r9d, byte ptr [rsi]
                test    r9b, r9b
                jz      short loc_7FF74A23167F
                mov     rcx, rax
                neg     ecx
                mov     edx, 0DEADC0DEh
                mov     eax, 55555555h
                xor     r8d, r8d
                jmp     short loc_7FF74A231668
; ---------------------------------------------------------------------------
                align 10h

loc_7FF74A231640:                       
                rol     eax, 0Ch
                xor     eax, r9d
                add     eax, 90F01234h

loc_7FF74A23164B:                       
                mov     r9d, edx
                add     r9d, r8d
                lea     edx, [r9+rcx]
                xor     edx, r9d
                xor     eax, edx
                movzx   r9d, byte ptr [rsi+r8+1]
                inc     r8
                test    r9b, r9b
                jz      short loc_7FF74A23168C

loc_7FF74A231668:                       
                movzx   r9d, r9b
                test    r9b, 1
                jz      short loc_7FF74A231640
                rol     eax, 1Dh
                add     eax, r9d
                add     eax, 0E5D4C3B3h
                jmp     short loc_7FF74A23164B
; ---------------------------------------------------------------------------

loc_7FF74A23167F:                       
                mov     eax, 55555555h
                mov     edx, 0DEADC0DEh
                xor     r8d, r8d

loc_7FF74A23168C:                       
                imul    r8d, r8d
                mov     ecx, r8d
                shl     ecx, 8
                rol     eax, 1Dh
                sub     ecx, r8d
                add     eax, edx
                xor     eax, ecx

                add     rsp, 20h
                pop     rsi
                ret
keygen endp

    end