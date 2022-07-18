psk:
	gcc -Wall -pedantic -lcrypto parallel_search_keyspace.c -o parallel_search_keyspace
clean:
	rm 	parallel_search_keyspace