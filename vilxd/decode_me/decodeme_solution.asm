  include     \masm64\include64\masm64rt.inc
    includelib  \masm64\lib64\msvcrt.lib 

    strcpy PROTO C :PTR BYTE, :PTR BYTE
 
    .data
      
      Source db "Pa100-322-1L@101", 0  

      Decoded db 64 dup(0)
      
    .code

entry_point proc

    invoke decodeme_main

    conout "The Password is ", ADDR Decoded, lf 

    waitkey

    invoke ExitProcess, 0

    ret

entry_point endp


decodeme_main proc                
                                        

Destination     equ byte ptr -358h
Str1            equ byte ptr -288h
Str2            equ byte ptr -1B8h
Str0            equ byte ptr -0E8h

                push    rdi
                push    rsi
                push    rbx
                sub     rsp, 360h
                lea     rsi, [rsp+378h+Destination]
                lea     rbx, [rsp+378h+Str1]

                mov     rdx, rsi              ; Destination
                lea     rcx, Source           ; "Pa100-322-1L@101"
                lea     rdi, [rsp+378h+Str0]
                call    transformChar

                lea     rsi, [rsp+378h+Destination]

                mov     rcx, offset Decoded
                mov     rdx, rsi
                call    strcpy

                add     rsp, 360h
                pop     rbx
                pop     rsi
                pop     rdi
                ret

decodeme_main   endp


transformChar   proc                    
                                        
                push    rbx
                sub     rsp, 20h
                mov     rbx, rcx
                mov     rcx, rdx        ; Destination
                mov     rdx, rbx        ; Source
                call    strcpy
                mov     rcx, rax
                movzx   eax, byte ptr [rbx]
                test    al, al
                jz      short loc_140001744
                xor     edx, edx
                jmp     short loc_140001730
; ---------------------------------------------------------------------------
                align 8

                loc_140001718:                          
                                cmp     al, 31h ; '1'
                                jz      short loc_140001750
                                cmp     al, 32h ; '2'
                                jnz     short loc_140001724
                                mov     byte ptr [rcx+rdx], 5Ch ; '\'

                loc_140001724:                          
                                                        
                                add     rdx, 1
                                movzx   eax, byte ptr [rbx+rdx]
                                test    al, al
                                jz      short loc_140001744

                loc_140001730:                          
                                                        
                                cmp     al, 30h ; '0'
                                jnz     short loc_140001718
                                mov     byte ptr [rcx+rdx], 5Fh ; '_'
                                add     rdx, 1
                                movzx   eax, byte ptr [rbx+rdx]
                                test    al, al
                                jnz     short loc_140001730

                loc_140001744:                          
                                                        
                                add     rsp, 20h
                                pop     rbx
                                ret
                ; ---------------------------------------------------------------------------
                                align 10h

                loc_140001750:                          
                                mov     byte ptr [rcx+rdx], 3Eh ; '>'
                                jmp     short loc_140001724
transformChar   endp

    end