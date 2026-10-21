#ifndef MANTLE_LIB_H
#define MANTLE_LIB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void mantle_free_string(char *s);

char *mantle_script_parse(const uint8_t *data, size_t len);

char *mantle_deserialize_block(const uint8_t *data, size_t len);

/* Returns 1 = ok, 0 = script failure, -1 = decode error. */
int mantle_verify_script(
    const uint8_t *script_pubkey, size_t script_pubkey_len,
    uint64_t amount,
    const uint8_t *tx_data, size_t tx_data_len,
    unsigned int input_idx,
    unsigned int flags,
    const uint64_t *spent_amounts,
    const uint8_t *const *spent_scripts,
    const size_t *spent_script_lens,
    size_t n_spent);

#ifdef __cplusplus
}
#endif

#endif /* MANTLE_LIB_H */
