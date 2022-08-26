import os
import random
import sys
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


def encryption(key, filename):
    # input size that we will pull out of the input file
    inputsize = 64 * 1024
    outFile = os.path.join(os.path.dirname(filename),
                           "(encrypted)"+os.path.basename(filename))
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = ''
# generating a  random IV of 16 bytes
    for i in range(16):
        IV += chr(random.randint(0, 0xFF))

    encryptor = AES.new(key, AES.MODE_CBC, IV)  # key, cipher block mode, IV

    with open(filename, "rb") as infile:
        with open(outFile, "wb") as outfile:
            outfile.write(filesize)
            outfile.write(IV)  # writting out to be used for decryption
            while True:
                byte = infile.read(inputsize)

                if len(byte) == 0:
                    break
        # if the size is not 16 bytes long then padding it with extra characters
                elif len(byte) % 16 != 0:
                    byte += ' ' * (16 - (len(byte) % 16))
                # encrypting the data
                outfile.write(encryptor.encryption(byte))


def decryption(key, filename):
    # first 11 is not filename
    outFile = os.path.join(os.path.dirname(filename),
                           os.path.basename(filename[11:]))
    inputsize = 64 * 1024
    with open(filename, "rb") as infile:
        filesize = infile.read(16)
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outFile, "wb") as outfile:
            while True:
                byte = infile.read(inputsize)
                if len(byte) == 0:
                    break
                # decyrpting the data
                outfile.write(decryptor.decryption(byte))

            # truncate the padding at the back of the padding process
            outfile.truncate(int(filesize))


def allfiles():
    allFiles = []
    for root, subfiles, files in os.walk(os.getcwd()):
        for names in files:
            allFiles.append(os.path.join(root, names))

    return allFiles


# user prompts
choice = user_input("Do you want to (E)ncrypt or (D)ecrypt? ")
password = user_input("Enter the password: ")

encFiles = allfiles()

if choice == "E":
    for files in encFiles:
        if os.path.basename(files).startswith("(encrypted)"):
            print("%s is already encrypted" % str(files))
            pass

        elif files == os.path.join(os.getcwd(), sys.argv[0]):
            pass
        else:
            # entering the hash of the password with the SHA256 function
            encryption(SHA256.new(password).digest(), str(files))
            print("Done encrypting %s" % str(files))
            os.remove(files)


elif choice == "D":
    filename = user_input("Enter the filename to decrypt: ")
    if not os.path.exists(filename):
        print("The file does not exist")
        sys.exit(0)
    elif not filename.startswith("(encrypted)"):
        print("%s is already not encrypted" % filename)
        sys.exit()
    else:
        # entering the hash of the password with the SHA256 function
        decryption(SHA256.new(password).digest(), filename)
        print("Done decrypting %s" % filename)
        os.remove(filename)

else:
    print("Please choose a valid command.")
    sys.exit()
