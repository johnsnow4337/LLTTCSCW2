f = open("/lib/i386-linux-gnu/libc.so.6", "rb")
filebytes = f.read()
print(hex(filebytes.find(b"/bin/sh\x00")))
f.close()