#!/bin/bash

for f in *key
do
	prefix=$(echo "$f" | cut -f1 -d.)
	openssl pkey -pubout -inform pem -outform pem -in "$prefix.key" -out "$prefix.pub"
done
