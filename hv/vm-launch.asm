.code

; bool __vm_launch();
?vm_launch@hv@@YA_NXZ proc
  extern hv_vmx_vmwrite_raw : proc

  ; Save the entry RSP (contains the return address back to the C++ caller).
  mov r8, rsp

  ; Windows x64: reserve shadow space + align for calls.
  sub rsp, 28h

  ; VMCS_GUEST_RSP (0x681C) = entry RSP
  mov rcx, 681Ch
  mov rdx, r8
  call hv_vmx_vmwrite_raw

  ; VMCS_GUEST_RIP (0x681E) = <successful_launch>
  mov rcx, 681Eh
  lea rdx, successful_launch
  call hv_vmx_vmwrite_raw

  add rsp, 28h

  vmlaunch

  ; if we reached here, then we failed to launch
  xor al, al
  ret

successful_launch:
  mov al, 1
  ret
?vm_launch@hv@@YA_NXZ endp

end

