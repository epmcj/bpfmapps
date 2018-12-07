ldxb r2, [r1+1]
lsh r2, 0x8
ldxb r3, [r1]
or r2, r3
ldxb r3, [r1+2]
ldxb r1, [r1+3]
lsh r1, 0x8
or r1, r3
lsh r1, 0x10
or r1, r2
mov r0, 0x1
mov r2, 0x0
jeq r1, r2, +1
mov r0, 0x0
exit
