#!/usr/bin/env python3
#coding=utf-8

"""
AMI PFAT Extract
AMI BIOS Guard Extractor
Copyright (C) 2018-2020 Plato Mavropoulos
"""

print('AMI BIOS Guard Extractor v3.0_a1')

import os
import re
import sys
import ctypes
import struct

# Set ctypes Structure types
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

class PFAT_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Size',			uint32_t),		# 0x00
		('Checksum',		uint32_t),		# 0x04 Unknown 16-bits
		('Tag',				char*8),		# 0x04 _AMIPFAT
		('Flags',			uint8_t),		# 0x10
		# 0x11
	]
	
	def pfat_print(self) :
		print('\nPFAT Main Header:\n')
		print('    Size        : 0x%X' % self.Size)
		print('    Checksum    : 0x%0.4X' % self.Checksum)
		print('    Tag         : %s' % self.Tag.decode('utf-8'))
		print('    Flags       : 0x%0.2X' % self.Flags)

class PFAT_Block_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('PFATVerMajor',	uint16_t),		# 0x00
		('PFATVerMinor',	uint16_t),		# 0x02
		('PlatformID',		uint8_t*16),	# 0x04
		('Attributes',		uint32_t),		# 0x14
		('ScriptVerMajor',	uint16_t),		# 0x16
		('ScriptVerMinor',	uint16_t),		# 0x18
		('ScriptSize',		uint32_t),		# 0x1C
		('DataSize',		uint32_t),		# 0x20
		('BIOSSVN',			uint32_t),		# 0x24
		('ECSVN',			uint32_t),		# 0x28
		('VendorInfo',		uint32_t),		# 0x2C
		# 0x30
	]
	
	def __init__(self, count, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.count = count
	
	def get_flags(self) :
		attr = PFAT_Block_Header_GetAttributes()
		attr.asbytes = self.Attributes
		
		return attr.b.SFAM, attr.b.ProtectEC, attr.b.GFXMitDis, attr.b.FTU, attr.b.Reserved
	
	def pfat_print(self) :
		no_yes = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		platform = bytes([int.from_bytes(struct.pack('<B', val), 'little') for val in self.PlatformID]).strip(b'\x00')
		if platform.isalpha() : # STRING
			platform = platform.decode('utf-8')
		else : # GUID
			platform = ''.join('%0.2X' % int.from_bytes(struct.pack('<B', val), 'little') for val in self.PlatformID)
			platform = '{%s-%s-%s-%s-%s}' % (platform[:8], platform[8:12], platform[12:16], platform[16:20], platform[20:])
		
		print('\n        PFAT Block %s Header:\n' % self.count)
		print('            PFAT Version              : %d.%d' % (self.PFATVerMajor, self.PFATVerMinor))
		print('            Platform ID               : %s' % platform)
		print('            Signed Flash Address Map  : %s' % no_yes[f1])
		print('            Protected EC OpCodes      : %s' % no_yes[f2])
		print('            Graphics Security Disable : %s' % no_yes[f3])
		print('            Fault Tolerant Update     : %s' % no_yes[f4])
		print('            Attributes Reserved       : 0x%X' % f5)
		print('            Script Version            : %d.%d' % (self.ScriptVerMajor, self.ScriptVerMinor))
		print('            Script Size               : 0x%X' % self.ScriptSize)
		print('            Data Size                 : 0x%X' % self.DataSize)
		print('            BIOS SVN                  : %d' % self.BIOSSVN)
		print('            EC SVN                    : %d' % self.ECSVN)
		print('            Vendor Info               : 0x%X' % self.VendorInfo)
		
class PFAT_Block_Header_Attributes(ctypes.LittleEndianStructure):
	_fields_ = [
		('SFAM', uint32_t, 1), # Signed Flash Address Map
		('ProtectEC', uint32_t, 1), # Protected EC OpCodes
		('GFXMitDis', uint32_t, 1), # GFX Security Disable
		('FTU', uint32_t, 1), # Fault Tolerant Update
		('Reserved', uint32_t, 28)
	]

class PFAT_Block_Header_GetAttributes(ctypes.Union):
	_fields_ = [
		('b', PFAT_Block_Header_Attributes),
		('asbytes', uint32_t)
	]

class PFAT_Block_RSA(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint32_t),		# 0x00
		('Unknown1',		uint32_t),		# 0x04
		('PublicKey',		uint32_t*64),	# 0x08
		('Exponent',		uint32_t),		# 0x108
		('Signature',		uint32_t*64),	# 0x10C
		# 0x20C
	]
	
	def __init__(self, count, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.count = count
	
	def pfat_print(self) :
		RSAPublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.PublicKey))
		RSASignature = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Signature))
		
		print('\n        PFAT Block %s Signature:\n' % self.count)
		print('            Unknown 0                 : 0x%X' % self.Unknown0)
		print('            Unknown 1                 : 0x%X' % self.Unknown1)
		print('            Public Key                : %s [...]' % RSAPublicKey[:8])
		print('            Exponent                  : 0x%X' % self.Exponent)
		print('            Signature                 : %s [...]' % RSASignature[:8])

# Process ctypes Structure Classes
def get_struct(buffer, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = buffer[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= len(buffer)) or (fit_len < struct_len) :
		print('Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name))
		sys.exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure
	
if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	pfat = sys.argv[1:]
else :
	# Folder path
	pfat = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			pfat.append(os.path.join(root, name))

pfat_index = 0
pfat_pat = re.compile(b'_AMIPFAT.AMI_BIOS_GUARD_FLASH_CONFIGURATIONS', re.DOTALL)

for input_file in pfat :
	with open(input_file, 'rb') as in_file : buffer = in_file.read()
	final_image = b''
	block_name = ''
	block_count = 0
	blocks = []
	flags = ['Update','Unknown 1','Unknown 2','Unknown 3']
	
	pfat_match = pfat_pat.search(buffer)
	
	if not pfat_match : continue
	
	buffer = buffer[pfat_match.start() - 0x8:]
	
	pfat_hdr = get_struct(buffer, 0, PFAT_Header)
	
	hdr_size = pfat_hdr.Size
	hdr_data = buffer[0x11:hdr_size].decode('utf-8').splitlines()
	
	pfat_hdr.pfat_print()
	print('    Title       : %s' % hdr_data[0])
	
	for entry in hdr_data[1:] :
		entry_data = entry.split(' ')
		entry_data = [s for s in entry_data if s != '']
		entry_param = entry_data[1]
		entry_blocks = int(entry_data[2])
		entry_name = entry_data[3][1:]
		entry_flags = ','.join([flags[bit] for bit in range(4) if int(entry_data[0]) >> bit & 1])
		if not entry_flags : entry_flags = 'N/A'
		
		for i in range(entry_blocks) : blocks.append([entry_name, entry_param, entry_flags, i + 1, entry_blocks])
		
		block_count += entry_blocks
	
	block_start = hdr_size
	for i in range(block_count) :
		if blocks[i][0] != block_name : print('\n    %s (Parameter: %s, Flags: %s)' % (blocks[i][0], blocks[i][1], blocks[i][2]))
		block_hdr = get_struct(buffer, block_start, PFAT_Block_Header, ['%d/%d' % (blocks[i][3], blocks[i][4])])
		block_hdr_size = ctypes.sizeof(PFAT_Block_Header)
		block_script_size = block_hdr.ScriptSize
		block_script_data = buffer[block_start + block_hdr_size:block_start + block_hdr_size + block_script_size] # Script not parsed
		block_data_start = block_start + block_hdr_size + block_script_size
		block_data_end = block_data_start + block_hdr.DataSize
		block_hdr.pfat_print()
		
		block_rsa = get_struct(buffer, block_data_end, PFAT_Block_RSA, ['%d/%d' % (blocks[i][3], blocks[i][4])])
		block_rsa_size = ctypes.sizeof(PFAT_Block_RSA)
		block_rsa.pfat_print()
		
		final_image += buffer[block_data_start:block_data_end]
		
		block_name = blocks[i][0]
		block_start = block_data_end + block_rsa_size
		
	tail_data = buffer[block_start:] # Store any data after the end of PFAT
	
	if pfat_index :
		body_file = '%s_%d_PFAT.bin' % (os.path.basename(input_file)[:-11 if pfat_index <= 10 else -12], pfat_index)
		tail_file = '%s_%d_REST.bin' % (os.path.basename(input_file)[:-11 if pfat_index <= 10 else -12], pfat_index)
	else :
		body_file = 'Unpacked_%s_%d_PFAT.bin' % (os.path.basename(input_file), pfat_index)
		tail_file = 'Unpacked_%s_%d_REST.bin' % (os.path.basename(input_file), pfat_index)
	
	with open(body_file, 'wb') as final : final.write(final_image)
	
	if tail_data[:-0x100] != b'\xFF' * (len(tail_data) - 0x100) :
		with open(tail_file, 'wb') as final : final.write(tail_data)
		
		if pfat_pat.search(tail_data) :
			pfat_index += 1
			pfat.append(tail_file)
		else :
			pfat_index = 0
		
else :
	input('\nDone!')