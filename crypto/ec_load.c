#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "hblk_crypto.h"

int make_directory(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0700) == -1) {
            return 0; // Directory creation failed
        }
    }
    return 1; // Directory exists or created successfully
}

/**
 * ec_load - Loads an EC key pair from disk
 *
 * @folder: Path to the folder from which to load the keys
 *
 * Return: A pointer to the loaded EC key pair, or NULL on failure
 */
EC_KEY *ec_load(char const *folder)
{
    if (!folder)
        return NULL;

    char key_path[256];
    char pub_path[256];
    snprintf(key_path, sizeof(key_path), "%s/%s", folder, "key.pem");
    snprintf(pub_path, sizeof(pub_path), "%s/%s", folder, "key_pub.pem");

    FILE *key_file = fopen(key_path, "r");
    if (!key_file)
        return NULL;

    FILE *pub_file = fopen(pub_path, "r");
    if (!pub_file)
    {
        fclose(key_file);
        return NULL;
    }

    EC_KEY *key = PEM_read_ECPrivateKey(key_file, NULL, NULL, NULL);
    if (!key)
    {
        fclose(key_file);
        fclose(pub_file);
        return NULL;
    }

    if (PEM_read_EC_PUBKEY(pub_file, &key, NULL, NULL) == NULL)
    {
        EC_KEY_free(key);
        fclose(key_file);
        fclose(pub_file);
        return NULL;
    }

    fclose(key_file);
    fclose(pub_file);

    return key;
}
