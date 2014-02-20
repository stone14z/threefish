#include <threefishApi.h>
#include <skeinApi.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

///////////////////////////////////////////////////////////////////////////////
//
// Name:  threefishtest
//
// Purpose:
//    Write a sample cipher using Bruce Schneier's threefish encruyption engine
//    along with the threefish API referenced on http://www.schneier.com/threefish.html
//    The API code along with the threefish source is at https://github.com/wernerd/Skein3Fish.
//
//    All that is needed to use this code is the "c" directory from the github site
//    referenced above along with the attached Makefile.  This code has only been tested
//    on a 64-bit Linux (Ubuntu) machine.  It is command line only.  No attempt has been made to
//    port this code to any other OS nor to add any GUI.
//
//    The simply encrypts and decrypts individual files.  It encrypts if the passed file
//    does not end with the string "_3fish" otherwise it decrypts.
//
//    Only the 512 bit block size is used.  The cipher is used in ctr mode.  The algorithm
//    is described below.
//
//    The key is generated as the 524287th generation 512-bit Skein hash of the passphrase.
//
//    The first block is built from the Skein hash of the concatenation of the filename, the passphrase,
//    and the seconds and nanoseconds since midnight January 1st, 1970.  The time data forms a nonce
//    to ensure that a file never encrypts the same way twice.  The first 128 bits of this block
//    get used as the initial tweak that gets used to encrypt the second block.  The next 64 bits
//    contain the number of byte in the file; this is used during decryption.  This first block is
//    encrypted with a tweak value of zero.
//
//    Note: storing the file size in the initial block is non-standard and might allow for a
//          cryptanalytic attack that I am not aware of at this time. I assumed, possibly erroneously,
//          that this would not introduce additional weakness in the algorithm sinve the block
//          gets encrypted
//
//    The second block is the passphrase.  It is encrypted using the itself as the key and the
//    first 128 bits of plaintext from the first block as the tweak.
//
//    The file is encrypted by incrementing the tweak value, reading the next 64 bytes of the file,
//    encrypting the those bytes, and continuing.  If the file does not end on a 64 byte boundary then
//    the block is zero padded.  
//
//    The reason for the > 500,000 hash generations to get the key is that, on my machine, anything
//    less than this and I could not detect, visually, any delay in the output when decrypting a 64 byte
//    file.  I wanted to make this algorithm toughened against a brute force attack which requires
//    computational complexity.  My "yardstick" was whether I could see a delay after starting the
//    program before the prompt came back.  The reason for encrypting the key as the second block
//    was to make it easy to discern whether a valid passphrase has been entered without requiring
//    the user to decrypt the entire file first.
//
//    After running "make", just "sudo cp threefishtest /bin/3fish" then the command
//    "3fish passphrase filename" can be run from anywhere on any file.  The output
//    will be filename_3fish.  To decrypt, just run the command "3fish passphrase filename_3fish".
//
///////////////////////////////////////////////////////////////////////////////


#define ENCRYPT 1
#define DECRYPT 2
#define HASHREPS 0x7ffff

int main(int argc, char *argv[])
{
    uint8_t myBlockR[SKEIN_512_STATE_BYTES], myBlockW[SKEIN_512_STATE_BYTES];
    uint8_t myRandomP[SKEIN_512_STATE_BYTES], myRandomC[SKEIN_512_STATE_BYTES];
    uint64_t myKeyData[SKEIN_MAX_STATE_WORDS], myTweakData[SKEIN_MAX_STATE_WORDS];
    uint64_t packedIV[SKEIN_MAX_STATE_WORDS];
    uint8_t hashVal[SKEIN_512_STATE_BYTES];
    uint8_t hashHold[SKEIN_512_STATE_BYTES];
    uint8_t unpackedTime[SKEIN_512_STATE_BYTES];
    ThreefishKey_t  myKey;
    FILE * inputFile = NULL, * outputFile = NULL;
    SkeinCtx_t ctx;
    const uint8_t * passphrase_p;
    char inputFilename[80], outputFilename[80];
    const char * inputFilename_p = (const char *)(&outputFilename[0]);
    char * p_3fish = "3fish";
    char * foundString;
    int direction;
    size_t bytesRead;
    int zeroCount;
    uint64_t fileSize = SKEIN_512_STATE_BYTES;
    int bytesToWrite, i;
    int decryptIndex;
    struct timespec currentTime;
    struct stat buf;

    memset(myBlockR, 0, sizeof(myBlockR));
    memset(myBlockW, 0, sizeof(myBlockW));
    memset(myKeyData, 0, sizeof(myKeyData));
    memset(myTweakData, 0, sizeof(myTweakData));
    memset(inputFilename, 0, sizeof(inputFilename));
    memset(outputFilename, 0, sizeof(outputFilename));
    memset(unpackedTime, 0, sizeof(unpackedTime));

    // we are expecting "prog passphrase filename"
    if (argc < 3)  {
       printf ("passphrase and filename expected\n");
       return 1;
    }

    passphrase_p = (const uint8_t*)argv[1];
    strncpy(inputFilename, argv[2], strlen(argv[2]));
    strncpy(outputFilename, argv[2], strlen(argv[2]));

    // The validation of the passphrase will be done by comparing
    // the HASHREPS hash of the passphrase to the stored 2nd block
    // the HASHREPS hash of the passphrase is the master key and
    // will be used with a tweak of 0 for encrypt/decrypting the IV
    skeinCtxPrepare(&ctx, Skein512);
    skeinInit(&ctx, Skein512);
    skeinUpdate(&ctx, passphrase_p, strlen(argv[1]));
    skeinFinal(&ctx, &hashHold[0]); 

    for (i = 0; i < HASHREPS; i++) {
        skeinInit(&ctx, Skein512);
        skeinUpdate(&ctx, &hashHold[0], SKEIN_512_STATE_BYTES);
        skeinFinal(&ctx, &hashVal[0]); 
        memcpy( &hashHold[0], &hashVal[0], SKEIN_512_STATE_BYTES);
    }

    // now hashHold contains the HASHREPS generation hash of the passphrase
    // that will become the block following the nonce and it is used as the
    // key for encrypting the nonce

    if ((inputFile = fopen(argv[2], "rb")) == NULL) {
        printf("Could not open %s\n", argv[2]);
        return 1;
    }

    // the IV will be encrypted/decrypted with the tweak = 0
    Skein_Get64_LSB_First(myKeyData, hashHold,  Threefish512/64);
    threefishSetKey(&myKey, Threefish512, &myKeyData[0], &myTweakData[0]);

    // now check whether the file ends with _3fish.  If it does then we
    // need to decrypt the file, otherwise we will encrypt the file.

    if (memcmp(&inputFilename[strlen(inputFilename)-5], p_3fish, 5)) {

        direction = ENCRYPT;

        clock_gettime(CLOCK_REALTIME, &currentTime);
        Skein_Put64_LSB_First(myBlockW, (void *)&currentTime, sizeof(currentTime));

        // set up the IV by hashing the passphrase, filename, and time
        // The time is #second in Epoch and nanoseconds
        skeinInit(&ctx, Skein512);
        skeinUpdate(&ctx, passphrase_p, strlen(argv[1]));
        skeinUpdate(&ctx, (const uint8_t *)inputFilename, strlen(inputFilename));
        skeinUpdate(&ctx, myBlockW, sizeof(currentTime));
        skeinFinal(&ctx, &myBlockR[0]);

        // the tweak is the first 3 words, we will put the filelength
        // into the fourth word of the first block
        Skein_Get64_LSB_First(packedIV, myBlockR, Threefish512/64);

        myTweakData[0] = packedIV[0];   // the first 128 bits of the nonce
        myTweakData[1] = packedIV[1];   // are the starting tweak
        stat(inputFilename, &buf);
        packedIV[3] = buf.st_size;        
        Skein_Put64_LSB_First(myBlockR, packedIV, Threefish512/8);

        threefishEncryptBlockBytes(&myKey, myBlockR, myBlockW);

        // myBlockW contains first block of encrypted data to write
        // reset the key with the new tweak
        threefishSetKey(&myKey, Threefish512, &myKeyData[0], &myTweakData[0]);
        strcat(outputFilename, ".3fish");
    }
    else
    {
        direction = DECRYPT;
        fread((void *)myRandomP, 1, SKEIN_512_STATE_BYTES, inputFile);
        threefishDecryptBlockBytes(&myKey, myRandomP, myBlockW);
        Skein_Get64_LSB_First(packedIV, myBlockW, Threefish512/64);
        myTweakData[0] = packedIV[0];   // the first 128 bits of the nonce
        myTweakData[1] = packedIV[1];   // are the starting tweak
        fileSize = packedIV[3];         // get stored file size
        threefishSetKey(&myKey, Threefish512, &myKeyData[0], &myTweakData[0]);
        // now get encrypted hash of passphrase to validate passphrase
        fread((void *)myBlockR, 1, SKEIN_512_STATE_BYTES, inputFile);
        threefishDecryptBlockBytes(&myKey, myBlockR, myRandomP);
        if (memcmp(myRandomP, hashHold, SKEIN_512_STATE_BYTES)) {
            printf("Invalid passphrase entered\n");
            fclose(inputFile);
            return 1;
        }
        outputFilename[strlen(inputFilename)-6] = '\0';
    }

    // now we can clear the passphrase from memory
    memset(argv[1], 0, sizeof(argv[1]));

    if ((outputFile = fopen(outputFilename, "wb")) == NULL) {
        printf("Could not open %s\n", argv[2]);
    }

    // on encryption the first block will hold a random nonce that will be used
    // for the tweak value and the second block holds the encrypted version of the
    // HASHREPS generation hash of the passphrase.  This stops brute force guessing
    // of the passphrase by slowing the  
    if (ENCRYPT == direction) {
        // had to wait until the output file was opened before writing.
        // write encrypted nonce
        fwrite((void *)myBlockW, 1, SKEIN_512_STATE_BYTES, outputFile);
        // now that we have the tweak set, encrypt and store the HASHREPS
        // hash of the passphrase
        threefishEncryptBlockBytes(&myKey, hashHold, myBlockW);
        fwrite((void *)myBlockW, 1, SKEIN_512_STATE_BYTES, outputFile);
    }

    memset(myBlockR, 0, SKEIN_512_STATE_BYTES);

    while (fileSize &&
            (bytesRead = fread((void *)myBlockR, 1, SKEIN_512_STATE_BYTES, inputFile)))
    {
        if (++myTweakData[0] == 0) ++myTweakData[1];
        threefishSetKey(&myKey, Threefish512, &myKeyData[0], &myTweakData[0]);
        bytesToWrite = SKEIN_512_STATE_BYTES;

        if (ENCRYPT == direction) 
        {
            if (bytesRead < SKEIN_512_STATE_BYTES) {
                myBlockR[bytesRead] = SKEIN_512_STATE_BYTES - bytesRead -1;
            }
            threefishEncryptBlockBytes(&myKey, myBlockR, myBlockW);
        }
        else
        {
            threefishDecryptBlockBytes(&myKey, myBlockR, myBlockW);
            if (fileSize > SKEIN_512_STATE_BYTES) fileSize -= SKEIN_512_STATE_BYTES;
            else {
                bytesToWrite = fileSize;
                fileSize = 0;
            }
        }

        if (bytesRead && bytesToWrite)
            fwrite((void *)myBlockW, 1, bytesToWrite, outputFile);

        // need the block cleared in case next block is partial
        memset(myBlockR, 0, sizeof(myBlockR));
        memset(myBlockW, 0, sizeof(myBlockW));

        // if this was the last block then don't bother reading again
        if (bytesRead < SKEIN_512_STATE_BYTES) break;
    }

    fclose(inputFile);
    fclose(outputFile);

// clear out RAM

    memset(myBlockR, 0, sizeof(myBlockR));
    memset(myBlockW, 0, sizeof(myBlockW));
    memset(myKeyData, 0, sizeof(myKeyData));
    memset(myTweakData, 0, sizeof(myTweakData));
    memset(inputFilename, 0, sizeof(inputFilename));
    memset(outputFilename, 0, sizeof(outputFilename));
    memset(unpackedTime, 0, sizeof(unpackedTime));
    memset(hashHold, 0, sizeof(hashHold));
    memset(hashVal, 0, sizeof(hashVal));
    memset((void *)&myKey, 0, sizeof(myKey));

    return 0;
}
