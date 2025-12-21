.code

?vmx_vmcall@hv@@YA_KAEAUhypercall_input@1@@Z proc
  ; move input into registers
  mov rax, [rcx]       ; code
  mov rdx, [rcx + 10h] ; args[1]
  mov r8,  [rcx + 18h] ; args[2]
  mov r9,  [rcx + 20h] ; args[3]
  mov r10, [rcx + 28h] ; args[4]
  mov r11, [rcx + 30h] ; args[5]
  mov rcx, [rcx + 08h] ; args[0]

  vmcall

  ret
?vmx_vmcall@hv@@YA_KAEAUhypercall_input@1@@Z endp

; void __fastcall hv_queue_handshake_asm(queue_handshake_request const* req, queue_handshake_raw_response* resp)
hv_queue_handshake_asm proc
  ; rcx = req, rdx = resp
  push rbx
  push rsi
  push rdi

  mov rdi, rdx                ; resp
  mov r10, rcx                ; save req pointer to r10

  mov rax, 80000000h          ; leaf
  mov rbx, [r10]              ; queue VA
  mov rdx, [r10 + 10h]        ; magic
  mov r8d, [r10 + 8]          ; size (zero-extend)
  mov r9,  [r10 + 18h]        ; seed
  mov ecx, 09D2F4B1Ah         ; magic0 -> RCX
  mov rsi, 0C3E15A7Bh         ; magic1 -> RSI

  ; subleaf 固定 0，已写入 RCX（高 32 位可忽略）
  
  cpuid

  mov [rdi], rax
  mov [rdi + 8], rbx
  mov [rdi + 10h], rcx
  mov [rdi + 18h], rdx

  pop rdi
  pop rsi
  pop rbx
  ret
hv_queue_handshake_asm endp

end
