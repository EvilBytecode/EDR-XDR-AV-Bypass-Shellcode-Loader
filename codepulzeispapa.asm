section .data
    name db 'codepulzeispapa', 0          

section .text
global hello                    
hello:
    nop                          
    mov eax, ebx               
    mov ebx, edx                
    mov ebx, eax                
    nop                          
    mov edx, ebx               
    ret                         
