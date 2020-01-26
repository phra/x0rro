; parameter order is: %rdi, %rsi, %rdx, %rcx, %r8, %r9, then push the rest on the stack in reverse order
; 74	AUE_MPROTECT	ALL	{ int mprotect(caddr_t addr, size_t len, int prot); }

_save_registers:
    push rdi
    push rsi
    push rdx
    push rcx
    push rax
{{#sections_mprotect}}
_mprotect{{{name}}}:
    lea rdi, [{{{page_start}}}]
    mov rsi, {{{psize}}}
    mov rdx, 0x7 ; rwx
    mov rax, 0x02
    shl rax, 24
    or rax, 74 ; mprotect
    syscall
{{/sections_mprotect}}
{{#sections_xor}}
    lea rdi, [{{{vaddr}}}]
    mov rcx, rdi
    add rcx, {{{vsize}}}
xor_loop{{{name}}}:
    xor byte ptr [rdi], {{{xor_key}}}
    inc rdi
    cmp rdi, rcx
    jl xor_loop{{{name}}}
{{/sections_xor}}
_restore_registers:
    pop rax
    pop rcx
    pop rdx
    pop rsi
    pop rdi
original_instructions:
    lea rdi, [{{{entry_point}}}]
    mov rcx, {{{entry_point_bytes}}}
    mov [rdi], rcx
jmp_back:
    jmp {{{entry_point}}}
