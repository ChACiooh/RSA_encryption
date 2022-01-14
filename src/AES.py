import random
import hashlib
import sys
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import time

time.clock = time.process_time	# It's necessary in upper ver than 3.7x of python

### AES and hash ###
BS = AES.block_size
mode = AES.MODE_CBC		# Cipher Block Chaining

def gen_random_iv():	# generate random initial vector with 1byte*BS
	iv = []
	for i in range(BS):
		iv.append(int(random.uniform(0, 255)))
	return bytes(iv)

def fit_str_blk(bs, s):
	return bs - (len(s) % bs)

def gen_using_key(key):
	length = fit_str_blk(BS, key.encode())
	key += chr(length) * length
	return key

def gen_byte_key(key):
	return hashlib.sha256(key.encode()).digest()	# use hash function
	
def AES_Encrypt(key, plain):
	length = fit_str_blk(BS, plain.encode())		# it can cover 한글 even
	#print("length of input data:"+str(len(plain))+'\n')
	plain = plain + chr(length) * length
	iv = gen_random_iv()
	encryptor = AES.new(key, mode, IV=iv)
	return (encryptor.encrypt(plain), iv)

def AES_Decrypt(key, iv, cipher):
	encryptor = AES.new(key, mode, IV=iv)
	plain = encryptor.decrypt(cipher)
	plain = plain[0:-plain[-1]]
	return plain.decode()
	
def len_String(length):
	txt = ''
	for i in range(100):
		txt += chr(int(random.uniform(32, 126)))	# readable alphabet and number
	return txt


#opt = 'This is a scentense for this practice.'	# original plain text
opt = str(input('input text to encrypt(in 100bytes)> '))
#opt = len_String(100)
print('[original plain text]:\n{}'.format(opt))
print('[length of plain txt]:{}'.format(len(opt)))

key = input('[register key string(maximum 32bytes available)]> ')
encryptedKey = gen_byte_key(str(key))	# for saving and match to another algorithms
key = gen_using_key(key)		# internally used key
print('[used hash type:(SHA256)] encrypted key:\n'+str(encryptedKey))

EandI = AES_Encrypt(key, opt)
De = AES_Decrypt(key, EandI[1], EandI[0])
print('[AES_CBC, SHA256 result]')
print('[encrypted]:\n'+str(EandI[0]))
print('[decrypted]:\n'+De)
print('')

### RSA ###

#key = ''	# remove after remove footnote above
err_trial = 0
while err_trial < 5:
	kSize = input('[input key size for RSA](1024/2048)> ')
	err_trial += 1
	try:
		kSize = int(kSize)
	except ValueError:
		print('{} is not integer value.'.format(kSize))
		print('error try - {}/5'.format(err_trial))
		continue
	if kSize == 1024 or kSize == 2048:
		key = RSA.generate(kSize)
		break
	else:
		print('please input 1024 or 2048 only.')
		print('error try - {}/5'.format(err_trial))

if err_trial >= 5:
	print('trial is over.')
	sys.exit()

KU = key.publickey()
cipher = KU.encrypt(opt.encode(), 32)
cipher_txt = cipher[0]

plain_txt = key.decrypt(cipher_txt).decode()

print('RSA encryption')
print('[encrypted]:\n'+str(cipher_txt))
print('[decrypted]:\n'+plain_txt)

