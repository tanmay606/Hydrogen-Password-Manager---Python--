from os import unlink,getenv

class Eraser(object):
	#!method just to delete plaintext database after operations.
	def __init__(self,filename):
		self.filename=filename
	def RunEraser(self):
		try:
			user_path = getenv('userprofile')
			chdir(user_path)
		except:
			pass
		try:
			unlink(self.filename)
		except:
			pass