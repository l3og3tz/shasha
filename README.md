shasha-1.0
======

shasha-1.0

  This python script attempts to crack passwords hashes using the dictionary attack method. By supplying the program with a
wordlist, the program runs through each word in the wordlist and attempts to crack each line of password hash. 

Types of Hashes

  The application works with several password hash types, namely SHA-256, SHA-512, MD-5, Blowfish(bcrypt), and NTLM for
  windows. The password hashes are automatically downloaded into the "retrieved_hashes.txt" file included in the "src" folder.
  if you chose to use a different password file, you will need to edit the source to reflect that. Also, you should remember
  that, when this application is run on linux machines, it automatically downloads the password hash file into 
  "retrived_hashes.txt", so the appropriate line nees to be changed as well in the source code.

How To Use

The application can be run from a terminal or command window when used on windows. In my linux machine for example, i have
added the application to my system path and can simply call it by typing "shasha" and supplying it with the arguments for 
the password hash file and if required, a path to a downloaded windows hash file.

To Run

From Windows

1. python shasha.py -H <link_to_hashfile> -d <link_to_wordlist> -s <link_to_SAM_file>

2. The -s argument is optional, but necessary only if you wish to parse a downloaded windows hash_file. If you wish
   to crack windows hashes it is probably the best thing to do, the application expects a certain format the hashes when it
   reads the main hash file during execution. For example, many windows hash files may include the LM hashes passwords for each
   password hash line in the SAM file, this program removes it and works only with the NTLM version.

From Linux

1. ./shasha.py shasha.py -H <link_to_hashfile> -d <link_to_wordlist> -s <link_to_SAM_file>
   For a linux machine, the application automatically downloads the passwd file  from /etc

And the just wait for it to do its work. REMEMBER A DICTIONARY ATTACK PASSWORD CRACKR IS ONLY AS GOOD AS YOUR WORDLIST.
Personally, i don't think dictionary attacks should work these days, but you will be amazed how much they still do.

Questions OR Comments or if you have an idea for adding a funtionality
l3og3tz gmail
