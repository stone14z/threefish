
all: threefishtest

threefishtest: threefishtest.o threefishApi.o threefish512Block.o threefish256Block.o \
	threefish1024Block.o skein_block.o skeinApi.o \
	skein.o
	g++ threefishtest.o threefishApi.o threefish512Block.o threefish256Block.o \
	threefish1024Block.o skein_block.o skeinApi.o \
	skein.o -lrt -o threefishtest

threefishtest.o: threefishtest.c
	g++ -c -I ./include threefishtest.c

threefishApi.o: threefishApi.c
	g++ -c -I ./include threefishApi.c

threefish512Block.o: threefish512Block.c
	g++ -c -I ./include threefish512Block.c

threefish256Block.o: threefish256Block.c
	g++ -c -I ./include threefish256Block.c

threefish1024Block.o: threefish1024Block.c
	g++ -c -I ./include threefish1024Block.c

skein.o: skein.c
	g++ -c -I ./include skein.c

skein_block.o: skein_block.c
	g++ -c -I ./include skein_block.c

skeinApi.o: skeinApi.c
	g++ -c -I ./include skeinApi.c

clean:
	rm -rf *o 
