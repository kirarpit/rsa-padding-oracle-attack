from Crypto.PublicKey import RSA

class RSACipher():

    def __init__(self):
        """
        Generate a RSA key pair for server
        """
        publicKeyFileName = "serverPublicKey"
        privateKeyFileName = "serverPrivateKey.pem"
        try:
            f = open(privateKeyFileName, 'rb')
            self.keys = RSA.importKey(f.read())
        except:
            self.keys = RSA.generate(1024)
            self.publickey = self.keys.publickey()
            # export public and private keys
            privHandle = open(privateKeyFileName, 'wb')
            privHandle.write(self.keys.exportKey('PEM'))
            privHandle.close()
            
            pubHandle = open(publicKeyFileName, 'wb')
            pubHandle.write(self.keys.publickey().exportKey())
            pubHandle.close()
        self.publickey = self.keys.publickey()
        
    def get_n(self):
        """
        Returns the public RSA modulus.
        """
        return self.keys.n

    def get_e(self):
        """
        Returns the public RSA exponent.
        """
        return self.keys.e

    def get_k(self):
        """
        Returns the length of the RSA modulus in bytes.
        """
        return (self.keys.size() + 1) // 8

    def decrypt(self, ciphertext):
        """-
        Decrypt a ciphertext
        """
        return self.keys.decrypt(ciphertext)

    def encrypt(self, message):
        """
        Encrypt a message
        """
        return self.publickey.encrypt(message, 32)
