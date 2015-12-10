all: groupsecure getsecure addsecure

groupsecure:groupsecure.c
	gcc -o groupsecure groupsecure.c -lcl -ldl -lresolv -lpthread -Lcl342 -Icl342

getsecure:getsecure.c
	gcc -o getsecure getsecure.c -lcl -ldl -lresolv -lpthread -Lcl342 -Icl342

addsecure:addsecure.c
	gcc -o addsecure addsecure.c -lcl -ldl -lresolv -lpthread -Lcl342 -Icl342


clean:
	rm groupsecure
	rm getsecure
	rm *.enc*