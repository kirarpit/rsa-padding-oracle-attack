import argparse
import socket
import sys
import os
import time
from aes import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
from random import randint

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress", help='ip address where the server is running', required=True)
parser.add_argument("-p", "--port", help='port where the server is listening on', required=True)
parser.add_argument("-m", "--message", help='message to send to the server', required=True)

#parser.add_argument("-b", "--block", help='the 32-byte block sent to the server', required=True)
#parser.add_argument("-id", "--keyid", help='unique key id', required=True)
args = parser.parse_args()

# load server's public key
serverPublicKeyFileName = "yubaPubKey"
f = open(serverPublicKeyFileName,'r')
RSAPubKey = RSA.importKey(f.read())
MESSAGE_LENGTH = 15

def getConnection():
	# Create a TCP/IP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# Connect the socket to the port where the server is listening
	server_address = (args.ipaddress, int(args.port))
	sock.connect(server_address)
	
	return sock

def toggleFirstBit(key):
	print "Bit Flipped"
	print "Old Key", key

	if key >= 2**127:
		key -= 2**127
	else:
		key += 2**127
	
	print "New Key", key
	return key
	
"""
- RSA can encrypt plaintext of limited size(128 bytes), that's why generally keys are encrypted and not plaintext
- That's why encrypted output would always be of size 128 bytes(1 Mb)
"""
def shiftRSACipher(cipher, key, bits):
	new_cipher = (bytes_to_long(cipher) * ((2**(bits * key.e)) % key.n)) % key.n
	return long_to_bytes(new_cipher, 128)

def sendPayload(payload, messageLength):
	sock = getConnection()
	sock.sendall(payload)

	# Look for the response
	amount_received = 0
	amount_expected = messageLength

	"""
	  - AES block size is 128bits(16 bytes | 16 char of the message)
	  - Hence, encrypted message length would always be int(m/16)*16 + (m%16)? 16:0
	  - Therefore, that's the length of data returned from server is expected to be above length
	"""
	if amount_expected % 16 != 0:
		amount_expected += (16 - (messageLength % 16))

	print "Message Length:", messageLength 
	print "Expected Length:", amount_expected
	answer = ""

	if amount_expected > amount_received:
		while amount_received < amount_expected:
			data = sock.recv(MESSAGE_LENGTH)
			print "Data received length:", len(data)

			amount_received += len(data)
			answer += data

	sock.close()
	if answer == "":
		print "Empty Response"

	return answer

AESKey = 2**127
AESKey = 145539436623726128093418598823574531036

file_ob = open('cipher.txt', "r")
content = file_ob.read()

cipher = content[:256].strip()
cipher = long_to_bytes(int(cipher, 16), 128)

encryptedMessage = content[256:].strip()
encryptedMessage = long_to_bytes(int(encryptedMessage, 16))

file_ob.close()

for i in reversed(range(0, 128)):
	print "Bit Shifted by", i
	if i != 127:
		AESKey = AESKey >> 1
	print "AES Key: ", AESKey
		
	aes = AESCipher(long_to_bytes(AESKey, 16))

	payload = shiftRSACipher(cipher, RSAPubKey, i)
	payload = cipher

	message = "Hello World!" + str(randint(0, 9))
	payload += aes.encrypt(message)
	print "Payload Length: ", len(payload)

	response = sendPayload(payload, len(message))

	print "Response: ", aes.decrypt(response)
	print "Expected Response: ", message.upper()

	if aes.decrypt(response).strip() != message.upper().strip():
		AESKey = toggleFirstBit(AESKey)
		
	break
	time.sleep(5)

aes = AESCipher(long_to_bytes(AESKey, 16))
print "Decrypted Message: ", aes.decrypt(encryptedMessage)
