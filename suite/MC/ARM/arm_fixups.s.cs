# CS_ARCH_ARM, CS_MODE_ARM, None
A,A,A,0xeb = bl _printf
A,0x90'A',0b0000AAAA,0xe3 = movw r9, :lower16:_foo
A,0x90'A',0b0000AAAA,0xe3 = movw r9, :lower16:_foo
A,0x90'A',0b0100AAAA,0xe3 = movt r9, :upper16:_foo
A,0x20'A',0b0000AAAA,0xe3 = movw r2, :lower16:fred
A,0b0000AAAA,0x80,0xe2 = add r0, r0, #L1-L2
