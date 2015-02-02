# Makefile para o projeto LabLock

default : 
	echo Usage: make [compile, run, test, clean]
	
compile : LabLock.c
	cc LabLock.c -o LabLock
	
run :
	./LabLock
	
test :
	make compile
	make run
	
clean :
	rm LabLock
