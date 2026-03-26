; Repro for INT 13h flags propagation bug in BIOS-stub path.
;
; This test intentionally sets CF before calling INT 13h AH=41h
; ("check extensions present"). On success the BIOS handler clears CF.
; A buggy emulator that does not copy the modified FLAGS back to the
; saved interrupt frame will return with CF still set after IRET.
;
; Expected results:
;   - Correct emulator / real BIOS / QEMU: PASS, FLAGS low bit clear
;   - Buggy emulator: FAIL_CF_SET, even though BX=AA55 and CX=0007
;
; Build:
;   nasm -f bin test_int13_flags.asm -o test_int13_flags.img
;
; Run:
;   python emulator.py test_int13_flags.img -m 1000

BITS 16
ORG 0x7C00

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti
    cld

    mov si, msg_banner
    call print_string

    stc                     ; make the bug deterministic
    mov ax, 0x4100          ; AH=41h, AL=00h
    mov bx, 0x55AA          ; required signature
    mov dl, 0x80            ; fixed disk
    int 0x13

    pushf
    pop ax
    mov [saved_flags], ax
    mov [saved_bx], bx
    mov [saved_cx], cx

    jc .fail_cf_set         ; movs above do not modify flags

    cmp bx, 0xAA55
    jne .fail_bad_bx

    cmp cx, 0x0007
    jne .fail_bad_cx

    mov si, msg_pass
    call print_string
    jmp show_state

.fail_cf_set:
    mov si, msg_fail_cf
    call print_string
    jmp show_state

.fail_bad_bx:
    mov si, msg_fail_bx
    call print_string
    jmp show_state

.fail_bad_cx:
    mov si, msg_fail_cx
    call print_string

show_state:
    mov si, msg_flags
    call print_string
    mov ax, [saved_flags]
    call print_hex16

    mov si, msg_bx
    call print_string
    mov ax, [saved_bx]
    call print_hex16

    mov si, msg_cx
    call print_string
    mov ax, [saved_cx]
    call print_hex16

    mov si, msg_crlf
    call print_string

halt:
    hlt
    jmp halt

print_string:
    lodsb
    test al, al
    jz .done
    call print_char
    jmp print_string
.done:
    ret

print_char:
    push ax
    push bx
    mov ah, 0x0E
    mov bh, 0x00
    int 0x10
    pop bx
    pop ax
    ret

print_hex16:
    push ax
    mov al, ah
    call print_hex8_from_al
    pop ax
    call print_hex8_from_al
    ret

print_hex8_from_al:
    push ax
    shr al, 4
    call print_hex_nibble
    pop ax
    and al, 0x0F
    call print_hex_nibble
    ret

print_hex_nibble:
    and al, 0x0F
    cmp al, 10
    jb .digit
    add al, 'A' - 10
    jmp .emit
.digit:
    add al, '0'
.emit:
    call print_char
    ret

msg_banner db 'INT13 AH=41h carry propagation test', 13, 10, 0
msg_pass   db 'PASS', 13, 10, 0
msg_fail_cf db 'FAIL_CF_SET', 13, 10, 0
msg_fail_bx db 'FAIL_BAD_BX', 13, 10, 0
msg_fail_cx db 'FAIL_BAD_CX', 13, 10, 0
msg_flags  db 'FLAGS=', 0
msg_bx     db ' BX=', 0
msg_cx     db ' CX=', 0
msg_crlf   db 13, 10, 0

saved_flags dw 0
saved_bx    dw 0
saved_cx    dw 0

times 510-($-$$) db 0
dw 0xAA55
