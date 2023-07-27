#include <stdlib.h>
#include "hblk_crypto.h"

EC_KEY *ec_create(void)
{
    EC_KEY *key = NULL;
    EC_GROUP *group = NULL;

    /* Création d'une nouvelle structure EC_KEY */
    key = EC_KEY_new();
    if (!key)
        return NULL;

    /* Sélection de la courbe elliptique secp256k1 */
    group = EC_GROUP_new_by_curve_name(EC_CURVE);
    if (!group)
    {
        EC_KEY_free(key);
        return NULL;
    }

    /* Génération de la clé privée et de la paire de clés */
    if (EC_KEY_set_group(key, group) != 1 || EC_KEY_generate_key(key) != 1)
    {
        EC_KEY_free(key);
        EC_GROUP_free(group);
        return NULL;
    }

    /* Libération de la mémoire utilisée pour le groupe elliptique */
    EC_GROUP_free(group);

    return key;
}
