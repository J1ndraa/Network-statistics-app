CC=g++
SOURCE=isa-top.cpp
FLAGS=-std=c++20 -Wall -lpcap -lncurses
BIN=isa-top
LOGIN=xhalva05
PDF_DOC=cz_manual.pdf
MAN_PAGE=cz_isa-top.1

all:
	$(CC) $(SOURCE) $(FLAGS) -o $(BIN)

pack:
	tar cvf $(LOGIN).tar $(SOURCE) $(PDF_DOC) $(MAN_PAGE) Makefile

clean:
	rm -f $(BIN)
	rm -f $(LOGIN).zip
