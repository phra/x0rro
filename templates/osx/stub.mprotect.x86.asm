; i386 syscall args: ebx ecx edx esi edi ebp
; 0x7d	i386	mprotect	sys_mprotect

_save_registers:
    ;and esp, 0xFFFFFFF0
    ;pushad
    push edx
    push ecx
    push ebx
    push eax
    push ebp
    ;pushfd
_call_get_eip:
    call _get_eip:
_get_eip:
    pop ebp
{{#sections_xor}}
    push 0x7 ; rwx
    push {{{psize}}}
    lea ebx, [ebp + {{{page_start}}}]
    push ebx
    mov eax, 0x7d ; mprotect osx
    int 0x80
    lea edi, [ebp + {{{vaddr}}}]
    mov ecx, edi
    add ecx, {{{vsize}}}
_xor_loop{{{name}}}:
    xor byte ptr [edi], {{{xor_key}}}
    inc edi
    cmp edi, ecx
    jl _xor_loop{{{name}}}
{{/sections_xor}}
_restore_registers:
    ;popfd
    ;popad
    lea edi, [ebp + {{{entry_point}}}]
    pop ebp
    pop eax
    pop ebx
    pop ecx
    pop edx
    cld
_jmp_back:
    jmp edi
