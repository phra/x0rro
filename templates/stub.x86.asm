; i386 syscall args: ebx ecx edx esi edi ebp
; 0x7d	i386	mprotect	sys_mprotect

_save_registers:
    push edx
    push ecx
    push ebx
    push eax
    push ebp
_call_get_eip:
    call _get_eip:
_get_eip:
    pop ebp
{{#sections_xor}}
    lea edi, [ebp + {{{vaddr}}}]
    mov ecx, edi
    add ecx, {{{vsize}}}
_xor_loop{{{name}}}:
    xor byte ptr [edi], {{{xor_key}}}
    inc edi
    cmp edi, ecx
    jl _xor_loop{{{name}}}
{{/sections_xor}}
_restore_original_instructions:
    lea edi, [ebp + {{{entry_point}}}]
    mov ecx, {{{entry_point_bytes}}}
    mov [edi], ecx
_restore_registers:
    pop ebp
    pop eax
    pop ebx
    pop ecx
    pop edx
_jmp_back:
    jmp edi
