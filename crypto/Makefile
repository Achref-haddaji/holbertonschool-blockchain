# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Werror -pedantic
LDFLAGS := -lssl -lcrypto

# Source files and object files
SRC := sha256.c ec_create.c ec_to_pub.c ec_from_pub.c ec_save.c ec_load.c ec_sign.c ec_verify.c
OBJ := $(SRC:.c=.o)

# Output library name
LIB := libhblk_crypto.a

# Build rules
all: $(LIB)

$(LIB): $(OBJ)
	ar -rc $(LIB) $(OBJ)
	ranlib $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(LIB)

re: fclean all
