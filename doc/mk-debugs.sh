cat ../src/*.c \
	| grep DEBUG: \
	| sed -e 's/ \* DEBUG: //' \
	| sort -n +1
