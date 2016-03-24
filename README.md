threefish
=========

Encrypt a file using threefish in TAE mode.

This is a simple program written to run from the command line in Linux.  It takes
two arguments, passpharse and filename.  If the filename does not end with "_3fish"
then the program creates an encrypted file with that string appended.  If the
filename ends with the string "_3fish" then the program decrypts into a file with
that string removed from the filename.

The program creates an IV using Skein as a PRNG by concatenating the filename,
passphrase, and time (seconds, nanoseconds in epoch).  It then uses the first
128 bits as the tweak for the second block and increments the tweak for each
successive block.  The IV block does get encrypted.

In order to verify that the correct passphrase was entered the key is stored in
the second block.  When the second block is decrypted (with the tweak from the 
first block) the decrypted key is compared to the key in use.

In order to avoid a brute force attack, the key used is the 0x7ffff generation
Skein hash of the passphrase.

The createFile.sh uses the linux dd utility to generate a testfile.txt that is
null filled.  The hexdump utility can then be used to examine the cipher text
that is generated.

Most of the code comes from the wernerd submission.  I have added a Makefile,
threefishtest.c (the TAE mode file encryptor), and the createFile.sh.  The mode
is a slightly modified version of the TAE mode as described in "Tweable Block
Ciphers" by Moses Liskov, Ronald Rivest, and David Wagner.  Instead of xor'ing
the blocks of plaintext together to get a checksum, the Skein
hash of the plaintext is computed.
