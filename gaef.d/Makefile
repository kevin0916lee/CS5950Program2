all: groupsecure addsecure

groupsecure:
	gcc -o groupsecure groupsecure.c -lcl -ldl -lresolv -lpthread -Lcl342 -Icl342
addsecure:
	gcc -g -o addsecure addsecure.c -lcl -ldl -lresolv -lpthread -Lcl342 -Icl342
clean:
	rm groupsecure
