threefish
=========

Encrypt a file using threefish in CTR mode (tweak incremented each block).

This is a simple program written to run from the command line in Linux.  It takes
one argument, the filename.  If the filename does not end with "_3fish"
then the program creates an encrypted file with that string appended.  If the
filename ends with the string "_3fish" then the program decrypts into a file with
that string removed from the filename.

The program creates an IV using Skein as a PRNG by concatenating the filename,
passphrase, time (seconds, milliseconds in epoch), and 100 bytes from urandom.  
It then uses the first 128 bits as the tweak for the second block and increments 
the tweak for each successive block.  The IV block does get encrypted with a tweak
of 0.

In order to verify that the correct passphrase was entered the key is stored in
the second block.  When the second block is decrypted (with the tweak from the 
first block) the decrypted key is compared to the key in use.

In order to avoid a brute force attack, the argon2 KDF is used to grenerate the key
from the entered passphrase (entered when prompted).

The createFile.sh uses the linux dd utility to generate a testfile.txt that is
null filled.  The hexdump utility can then be used to examine the cipher text
that is generated.

Most of the code comes from the wernerd submission.  I have added a Makefile,
threefishtest.c (the encryptor that Bruce Schneier's threefish engine), and the 
createFile.sh.
