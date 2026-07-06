/* Transport security primitives — C ABI exposed by the Rust transportsec crate.
 * Ed25519: 32-byte seed, 32-byte public key, 64-byte signature.
 * X25519:  32-byte private scalar, 32-byte public point, 32-byte shared secret.
 * Return codes: 0 = OK, -1 = null pointer, -2 = bad key, -3 = verification failed.
 */
#ifndef TRANSPORTSEC_H
#define TRANSPORTSEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t ts_ed25519_keygen(uint8_t *seed_out, uint8_t *pub_out);
int32_t ts_ed25519_sign(const uint8_t *seed, const uint8_t *msg, size_t msg_len,
                        uint8_t *sig_out);
int32_t ts_ed25519_verify(const uint8_t *pubkey, const uint8_t *msg,
                          size_t msg_len, const uint8_t *sig);
int32_t ts_x25519_keygen(uint8_t *priv_out, uint8_t *pub_out);
int32_t ts_x25519_dh(const uint8_t *privkey, const uint8_t *peer_pub,
                     uint8_t *shared_out);

#ifdef __cplusplus
}
#endif

#endif /* TRANSPORTSEC_H */
