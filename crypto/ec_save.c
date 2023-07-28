#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

/**
 * ec_save - Save an existing EC key pair on the disk
 * @key: Pointer to the EC key pair to be saved on disk
 * @folder: Path to the folder in which to save the keys
 *
 * Return: 1 on success, 0 on failure
 */
int ec_save(EC_KEY *key, char const *folder)
{
	char private_key_path[512], public_key_path[512];
	FILE *private_key_file = NULL, *public_key_file = NULL;

	if (mkdir(folder, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == -1)
	{
		perror("Failed to create the folder");
		return (0);
	}

	/* Save the private key in PEM format */
	snprintf(private_key_path, sizeof(private_key_path), "%s/key.pem", folder);
	private_key_file = fopen(private_key_path, "w");
	if (!private_key_file)
	{
		perror("Failed to open private key file");
		return (0);
	}
	if (!PEM_write_ECPrivateKey(private_key_file, key, NULL, NULL, 0, NULL, NULL))
	{
		fprintf(stderr, "Failed to write private key\n");
		ERR_print_errors_fp(stderr);
	}
	fclose(private_key_file);

	/* Save the public key in PEM format */
	snprintf(public_key_path, sizeof(public_key_path), "%s/key_pub.pem", folder);
	public_key_file = fopen(public_key_path, "w");
	if (!public_key_file)
	{
		perror("Failed to open public key file");
		return (0);
	}
	if (!PEM_write_EC_PUBKEY(public_key_file, key))
	{
		fprintf(stderr, "Failed to write public key\n");
		ERR_print_errors_fp(stderr);
	}
	fclose(public_key_file);

	return (1);
}
