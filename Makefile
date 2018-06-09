
all: threefishtest

threefishtest: threefishtest.o threefishApi.o threefish512Block.o threefish256Block.o \
	threefish1024Block.o skein_block.o skeinApi.o \
	skein.o
	gcc threefishtest.o threefishApi.o threefish512Block.o threefish256Block.o \
	threefish1024Block.o skein_block.o skeinApi.o -L./argon2 -largon2 \
	skein.o  -o 3fish

threefishtest.o: threefishtest.c
	gcc -c -I ./include threefishtest.c

threefishApi.o: threefishApi.c
	gcc -c -I ./include threefishApi.c

threefish512Block.o: threefish512Block.c
	gcc -c -I ./include threefish512Block.c

threefish256Block.o: threefish256Block.c
	gcc -c -I ./include threefish256Block.c

threefish1024Block.o: threefish1024Block.c
	gcc -c -I ./include threefish1024Block.c

skein.o: skein.c
	gcc -c -I ./include skein.c

skein_block.o: skein_block.c
	gcc -c -I ./include skein_block.c

skeinApi.o: skeinApi.c
	gcc -c -I ./include skeinApi.c

clean:
	rm -rf *o 
