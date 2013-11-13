#!/usr/bin/env python
"""
Created on Aug 6, 2013

@author: L3o G3tz (l3og3tz@gmail.com)
"""

import crypt
import sys
import subprocess
import hashlib
import binascii
from optparse import OptionParser
from bcrypt import hashpw, gensalt
from threading import *

screenlock = Semaphore(value=1)

def clear():
    if("win" in sys.platform.lower()):
        subprocess.call("cls")
    elif ("linux" or "unix" in sys.platform.lower()):
        subprocess.call(["clear"])

    
def open_pass_file(the_pass_file):
    try:
        my_pass_file = open(the_pass_file)
        print ("[+] Successfully opened password hash file ""{0}"" for reading...".format(the_pass_file))
        return my_pass_file
    except IOError as ioerror:
        print ("[-] {}".format(ioerror)) 
        exit(0)

def open_dict_file(the_dict_file):
    try:
        my_dict_file = open(the_dict_file, "r")
        # print ("[+] Successfully opened ""{0}"" for reading...".format(the_dict_file))
        return my_dict_file
    except IOError as ioerror:
        print ("[-] {}".format(ioerror)) 
        exit(0) 

def identify_hash_type_and_crack(the_determinant, the_dict_file):
    """Identifies the hashing algorithm used in the encrypting the plain-text password"""
    if (the_determinant.split(":")[1].strip(" ")[0:3] == "$1$"):  # checks for a MD5
        username = the_determinant.split(":")[0]  # extracted username from password file.
        encryptedpassword = the_determinant.split(":")[1].strip(" ")  # extracted encrypted password
        crack_md5(username, encryptedpassword, the_dict_file)  # attempts to crack the password using MD5 dictionary attack
        print ""
    elif (the_determinant.split(":")[1].strip(" ")[0:2] == "$2"):
        username = the_determinant.split(":")[0] 
        encryptedpassword = the_determinant.split(":")[1].strip(" ")
        crack_bcrypt(username, encryptedpassword, the_dict_file)
        print ""
    elif (the_determinant.split(":")[1].strip(" ")[0:3] == "$5$"):
        username = the_determinant.split(":")[0] 
        encryptedpassword = the_determinant.split(":")[1].strip(" ")
        crack_sha_256(username, encryptedpassword, the_dict_file)
        print ""
    elif (the_determinant.split(":")[1].strip(" ")[0:3] == "$6$"):
        username = the_determinant.split(":")[0] 
        encryptedpassword = the_determinant.split(":")[1].strip(" ")
        crack_sha_512(username, encryptedpassword, the_dict_file)
        print ""
    elif (the_determinant.split(":")[1].strip(" ")[0:4] == "$NT$"):
        username = the_determinant.split(":")[0] 
        encryptedpassword = the_determinant.split(":")[1].strip(" ")
        crack_ntlm(username, encryptedpassword, the_dict_file)
        print ""
    else:
        username = the_determinant.split(":")[0] 
        encryptedpassword = the_determinant.split(":")[1].strip(" ")
        crack_simple_hash(username, encryptedpassword, the_dict_file)           
        print ""
    
                
def crack_simple_hash(the_user, the_crypted_password, the_dict_file):
    """Encrypts a simple hash where hash type is unknown"""  # may not necessarily work, more of a trial and error

    dictionary_file = open_dict_file(the_dict_file)

    try:
        
        dictionary_file = open_dict_file(the_dict_file)
        the_salt = the_crypted_password[0:2]  # salt
    
        screenlock.acquire()
        print "\033[1;35m[+] Retrieved User:{0} Encrypted Pass:{1}\033[1;m".format(the_user, the_crypted_password)
        print "\033[1;33m[+] Hashing Algorithm identified as Simple Hash/Unknown\033[1;m"
        print "\033[1;30m[+] Attempting to crack...\033[1;m"
            
        for word in dictionary_file.readlines():  # running through words in dictionary one at a time.
            word = word.strip("\n")
            the_crypt_word = crypt.crypt(word, the_salt)

            if(the_crypt_word == the_crypted_password):
                print "\033[1;42m[+] Found Password... User:{} Password:{}\033[1;m\n".format(the_user, word)
                return
   
        print "\033[1;41m[-] Password not found for {}\033[1;m\n".format(the_user)
        return
    
    except KeyboardInterrupt:
        screenlock.release()
        exit(0)
    except:
        screenlock.acquire()
        print "Encountered an unknown error"
        return
    finally:
        dictionary_file.close()
        screenlock.release()



def crack_sha_256(the_user, the_crypted_password, the_dict_file):
    """Encrypts a word from the dictionary using the SHA-256 algorithm and compares to the hashed password"""
    dictionary_file = open_dict_file(the_dict_file)
    
    try:
        
        the_sha_prefix = the_crypted_password[0:3]
        the_salt = the_crypted_password.split("$")[2].strip(" ")  # salt
        the_insalt = the_sha_prefix + the_salt + "$"  # a combination of the sha256 prefix($6$ and the salt
    
        screenlock.acquire()
        print "\033[1;35m[+] Retrieved User:{0} Encrypted Pass:{1}\033[1;m".format(the_user, the_crypted_password)
        print "\033[1;33m[+] Hashing Algorithm identified as SHA-256\033[1;m"
        print "\033[1;30m[+] Attempting to crack...\033[1;m"
    
        for word in dictionary_file.readlines():
            word = word.strip("\n")
            the_crypt_word = crypt.crypt(word, the_insalt)

            if(the_crypt_word == the_crypted_password):
                print "\033[1;42m[+] Found Password... User:{} Password:{}\033[1;m\n".format(the_user, word)
                return
        print "\033[1;41m[-] Password not found for {}\033[1;m\n".format(the_user)
        return
    
    except KeyboardInterrupt:
        screenlock.release()
        sys.exit(0)
    except:
        screenlock.acquire()
        print "Encountered an unknown error"
        return
    finally:
        dictionary_file.close()
        screenlock.release()
        
def crack_sha_512(the_user, the_crypted_password, the_dict_file):
    """Encrypts a word from the dictionary using the SHA-512 algorithm and compares to the hashed password"""
    
    dictionary_file = open_dict_file(the_dict_file)

    try:
        
        the_sha_prefix = the_crypted_password[0:3]
        the_salt = the_crypted_password.split("$")[2].strip(" ")
        the_insalt = the_sha_prefix + the_salt + "$"

        screenlock.acquire()
        print "\033[1;35m[+] Retrieved User:{0} Encrypted Pass:{1}\033[1;m".format(the_user, the_crypted_password)
        print "\033[1;33m[+] Hashing Algorithm identified as SHA-512\033[1;m"
        print "\033[1;30m[+] Attempting to crack...\033[1;m"
    
        for word in dictionary_file.readlines():
            word = word.strip("\n")
            the_crypt_word = crypt.crypt(word, the_insalt)

            if(the_crypt_word == the_crypted_password):
                print "\033[1;42m[+] Found Password... User:{} Password:{}\033[1;m\n".format(the_user, word)
                return
        print "\033[1;41m[-] Password not found for {}\033[1;m\n".format(the_user)
        return
    
    except KeyboardInterrupt:
        screenlock.release()
        sys.exit(0)
    except:
        screenlock.acquire()
        print "Encountered an unknown error"
        return
    finally:
        dictionary_file.close()
        screenlock.release()

def crack_md5(the_user, the_crypted_password, the_dict_file):
    """Encrypts a word from the dictionary using the MD5 algorithm and compares to the hashed password"""
    dictionary_file = open_dict_file(the_dict_file)

    try:
        
        dictionary_file = open_dict_file(the_dict_file)
        the_md5_prefix = the_crypted_password[0:3]
        the_salt = the_crypted_password.split("$")[2].strip(" ")
        the_insalt = the_md5_prefix + the_salt + "$"
    
        screenlock.acquire()
        print "\033[1;35m[+] Retrieved User:{0} Encrypted Pass:{1}\033[1;m".format(the_user, the_crypted_password)
        print "\033[1;33m[+] Hashing Algorithm identified as MD-5\033[1;m"
        print "\033[1;30m[+] Attempting to crack...\033[1;m"
    
        for word in dictionary_file.readlines():
            word = word.strip("\n")
            the_crypt_word = crypt.crypt(word, the_insalt)

            if(the_crypt_word == the_crypted_password):
                print "\033[1;42m[+] Found Password... User:{} Password:{}\033[1;m\n".format(the_user, word)
                return
        print "\033[1;41m[-] Password not found for {}\033[1;m\n".format(the_user)
        return
    
    except KeyboardInterrupt:
        screenlock.release()
        sys.exit(0)
    except:
        screenlock.acquire()
        print "Encountered an unknown error"
        return
    finally:
        dictionary_file.close()
        screenlock.release()
        
        
def crack_ntlm(the_user, the_crypted_password, the_dict_file):
    """Encrypts a word from the dictionary using the windows NTLM  algorithm and compares to the hashed password"""
    dictionary_file = open_dict_file(the_dict_file)

    try:
        ntlm_prefix = the_crypted_password[0:4]
    
        screenlock.acquire()
        print "\033[1;35m[+] Retrieved User:{0} Encrypted Pass:{1}\033[1;m".format(the_user, the_crypted_password)
        print "\033[1;33m[+] Hashing Algorithm identified as NTLM\033[1;m"
        print "\033[1;30m[+] Attempting to crack...\033[1;m"
            
        for word in dictionary_file.readlines():
            word = word.strip("\n")
            raw_crypt_word = hashlib.new("md4", word.encode("utf-16le")).digest()
            the_crypt_word = ntlm_prefix + binascii.hexlify(raw_crypt_word)

            if(the_crypt_word == the_crypted_password):
                print "\033[1;42m[+] Found Password... User:{} Password:{}\033[1;m\n".format(the_user, word)
                return
        print "\033[1;41m[-] Password not found for {}\033[1;m\n".format(the_user)
        return
    
    except KeyboardInterrupt:
        screenlock.release()
        sys.exit(0)
    except:
        screenlock.acquire()
        print "Encountered an unknown error"
        return
    finally:
        dictionary_file.close()
        screenlock.release()      
    

def crack_bcrypt(the_user, the_crypted_password, the_dict_file):
    """Encrypts a word from the dictionary using the bcrypt Blowfish algorithm and compares to the hashed password"""
    dictionary_file = open_dict_file(the_dict_file)

    try:
        # bcrypt_prefix = the_crypted_password[0:4]  #may be useful info one day
        # the_log_rounds = int(the_crypted_password.split("$")[2]) #the log_rounds, #may be useful info one day
    
        screenlock.acquire()
        print "\033[1;35m[+] Retrieved User:{0} Encrypted Pass:{1}\033[1;m".format(the_user, the_crypted_password)
        print "\033[1;33m[+] Hashing Algorithm identified as Bcrypt\033[1;m"
        print "\033[1;30m[+] Attempting to crack...\033[1;m"

        for word in dictionary_file.readlines():
            word = word.strip("\n")
            hash = the_crypted_password
        
            if(hashpw(word, hash) == the_crypted_password): 
                print "\033[1;42m[+] Found Password... User:{} Password:{}\033[1;m\n".format(the_user, word)
                return
        print "\033[1;41m[-] Password not found for {}\033[1;m\n".format(the_user)
        return
    
    except KeyboardInterrupt:
        screenlock.release()
        sys.exit(0)
    except:
        screenlock.acquire()
        print "Encountered an unknown error"
        return
    finally:
        dictionary_file.close()
        screenlock.release()


def download_shadow_file(the_file_name="/etc/shadow", the_out_file="retrieved_hashes.txt", option="w"):
    """Locates a *Nix based machines shadow file and downloads the hashes"""
    try:
        shadow_file = open(the_file_name, "r")
        output_file = open(the_out_file, option)
        for line in shadow_file.readlines():
            output_file.write(line)
        shadow_file.close()
        output_file.close()
    except IOError as ioerror:
        print ioerror

def read_sam_file(the_file_name, the_out_file = "retrieved_hashes.txt", option = "a"):
    """Locates a NT based machines SAM file and downloads the hashes
       Note - Ignores the LM Hash, Uses the NTLM hash only as LM is being faced out, LM
       Hashes is disabled on some machines. Uses NTLM to avoid further parsing"""
    try:
        sam_file = open(the_file_name, "r")
        output_file = open(the_out_file, option)
        prefix = "$NT$"
        for line in sam_file.readlines():
            if(":" in line):
                user = line.split(":")[0].strip("")
                hash = line.split(":")[3].strip("")
                line = user+":"+prefix+hash
                output_file.write(line+"\n")
        sam_file.close()
        output_file.close()
    except IOError as ioerror:
        print ioerror
        
   

def intro_about():
    clear()
    print """
                 *******************************************************************************
                 *                                                                             *
                 *                        Shasha Password Cracker                              *    
                 *                 Shasha Cracks Password Using The Famous                     *
                 *                         Dictionary Attack Method                            * 
                 *                               By l3og3tz                                    *
                 *                                                                             *
                 *******************************************************************************\n"""
def main():
    """Runs the program"""
    parser = OptionParser("usage%prog -H <password file> -d <dictionary file>\n")  # Command line options required for execution.
    parser.add_option("-H", "--hashfile", dest="hash_file", type="string", help="Specify password hash file DEFAULT=retrieved_hashes.txt")
    parser.add_option("-d", "--dictionary", dest="dictionary_file", type="string", help="Specify dictionary file")
    parser.add_option("-s", "--samfile", dest="dumped_sam_file", type="string", help="Specify a dumped SAM file to copy/parse hashes to main hash file.")
   
    options, args = parser.parse_args()
    
    # exits program and displays user info if the right number of arguments are not provided.
    if(options.hash_file == None) | (options.dictionary_file == None): 
        print (parser.usage)
        exit(0)
    else:  # continues with normal execution
        if("linux" or "unix" in sys.platform):
            print "Identified a *nix system"
            download_shadow_file()
            print "\033[1;33m[+] Downloaded Shadow File\033[1;m\n"
        if(options.dumped_sam_file):
            print "\033[1;33m[+] Parsing windows SAM File\033[1;m\n"
            read_sam_file(options.dumped_sam_file)
            print "\033[1;33m[+] SAM file successfully parsed into main hash file\033[1;m\n"
            print ""
            
        hashed_file = open_pass_file(options.hash_file)
        if(hashed_file):                
            # print ("Successfully opened both files.")
            for line in hashed_file.readlines():
                if (':' in line) or ("$" in line):
                    line = line.strip("\n")
                    t = Thread(target=identify_hash_type_and_crack, args=(line, options.dictionary_file))
                    t.start()
                    # print ""
        return 
    try:
        hashed_file.close()
    except IOError as ioerror:
        print(ioerror)  
                  
                  
if __name__ == "__main__":  # runs main.
    intro_about()
    main()
