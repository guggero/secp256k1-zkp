/**********************************************************************
 * Copyright (c) 2019 Jonas Nick, Andrew Poelstra                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

/**
 * This file demonstrates how to use the thresholdsig module to create a threshold signature.
 * Additionally, see the documentation in include/secp256k1_thresholdsig.h.
 */

#include <stdio.h>
#include <assert.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>
#include <secp256k1_thresholdsig.h>

 /* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS_TOTAL 3
#define N_SIGNERS 2
 /* Create a key pair and store it in seckey and pubkey */
int create_key(const secp256k1_context* ctx, unsigned char* seckey, secp256k1_pubkey* pubkey) {
    int ret;
    FILE *frand = fopen("/dev/urandom", "r");
    if (frand == NULL) {
        return 0;
    }
    do {
         if(!fread(seckey, 32, 1, frand)) {
             fclose(frand);
             return 0;
         }
    /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));
    fclose(frand);
    ret = secp256k1_ec_pubkey_create(ctx, pubkey, seckey);
    return ret;
}

/* Sign a message hash with the given key pairs and store the result in sig */
int sign(const secp256k1_context* ctx, unsigned char seckeys[][32], const secp256k1_pubkey* combined_pk, const secp256k1_pubkey* pubkeys, const unsigned char* msg32, secp256k1_schnorrsig *sig) {
    secp256k1_musig_session musig_session[N_SIGNERS];
    unsigned char nonce_commitment[N_SIGNERS][32];
    const unsigned char *nonce_commitment_ptr[N_SIGNERS];
    secp256k1_musig_session_signer_data signer_data[N_SIGNERS][N_SIGNERS];
    secp256k1_pubkey nonce[N_SIGNERS];
    int i, j;
    secp256k1_musig_partial_signature partial_sig[N_SIGNERS];
    size_t indices[N_SIGNERS];
    unsigned char pkser[33];
    size_t pkserlen = sizeof(pkser);

    printf("\"indicesOfActualSigners\": [");
    for (i = 0; i < N_SIGNERS; i++) {
        /* Use a "random" selection of signer indices, not necessarily in order */
        indices[i] = (i * 73) % N_SIGNERS_TOTAL;
        printf("%d", indices[i]);
        if (i < N_SIGNERS - 1) {
            printf(", ");
        }
    }

    printf("],\n\"sessionIds\": [\n");
    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char session_id32[32];

        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of secp256k1_musig_session_initialize. Otherwise
         * it's trivial for an attacker to extract the secret key! */
        frand = fopen("/dev/urandom", "r");
        if(frand == NULL) {
            return 0;
        }
        if (!fread(session_id32, 32, 1, frand)) {
            fclose(frand);
            return 0;
        }
        fclose(frand);
        /* Initialize session */
        if (!secp256k1_thresholdsig_session_initialize(ctx, &musig_session[i], signer_data[i], nonce_commitment[i], session_id32, msg32, combined_pk, indices, N_SIGNERS, indices[i], seckeys[indices[i]])) {
            return 0;
        }
        nonce_commitment_ptr[i] = &nonce_commitment[i][0];
        
        printf("  \"");
        for (j = 0; j < 32; j++) {
            printf("%02x", session_id32[j]);
        }
        printf("\",\n");
    }
    printf("],\n\"commitments\": [\n");
    for (i = 0; i < N_SIGNERS; i++) {
        printf("  \"");
        for (j = 0; j < 32; j++) {
            printf("%02x", nonce_commitment[i][j]);
        }
        printf("\",\n");
    }
    printf("],\n\"secretKeys\": [\n");
    for (i = 0; i < N_SIGNERS; i++) {
        printf("  \"");
        for (j = 0; j < 32; j++) {
            printf("%02x", musig_session[i].seckey[j]);
        }
        printf("\",\n");
    }
    printf("],\n\"secretNonces\": [\n");
    for (i = 0; i < N_SIGNERS; i++) {
        printf("  \"");
        for (j = 0; j < 32; j++) {
            printf("%02x", musig_session[i].secnonce[j]);
        }
        printf("\",\n");
    }
    /* Communication round 1: Exchange nonce commitments */
    for (i = 0; i < N_SIGNERS; i++) {
        /* Set nonce commitments in the signer data and get the own public nonce */
        if (!secp256k1_musig_session_get_public_nonce(ctx, &musig_session[i], signer_data[i], &nonce[i], nonce_commitment_ptr, N_SIGNERS)) {
            return 0;
        }
    }
    /* Communication round 2: Exchange nonces */
    for (i = 0; i < N_SIGNERS; i++) {
        for (j = 0; j < N_SIGNERS; j++) {
            if (!secp256k1_musig_set_nonce(ctx, &signer_data[i][j], &nonce[j])) {
                /* Signer j's nonce does not match the nonce commitment. In this case
                 * abort the protocol. If you make another attempt at finishing the
                 * protocol, create a new session (with a fresh session ID!). */
                return 0;
            }
        }
        if (!secp256k1_musig_session_combine_nonces(ctx, &musig_session[i], signer_data[i], N_SIGNERS, NULL, NULL)) {
            return 0;
        }
        if (i == 0) {
            printf("],\n\"nonceCombined\": \"");
            if (!secp256k1_ec_pubkey_serialize(ctx, pkser, &pkserlen, &musig_session[i].combined_nonce, SECP256K1_EC_COMPRESSED)) {
                return 0;
            }
            for (j = 0; j < pkserlen; j++) {
                printf("%02x", pkser[j]);
            }
            printf("\",\n");
        }
    }
    printf("\"partialSigs\": [\n");
    for (i = 0; i < N_SIGNERS; i++) {
        if (!secp256k1_musig_partial_sign(ctx, &musig_session[i], &partial_sig[i])) {
            return 0;
        }
        printf("  \"");
        for (j = 0; j < 32; j++) {
            printf("%02x", partial_sig[i].data[j]);
        }
        printf("\",\n");
    }
    printf("],\n");
    /* Communication round 3: Exchange partial signatures */
    for (i = 0; i < N_SIGNERS; i++) {
        for (j = 0; j < N_SIGNERS; j++) {
            /* To check whether signing was successful, it suffices to either verify
             * the the combined signature with the combined public key using
             * secp256k1_schnorrsig_verify, or verify all partial signatures of all
             * signers individually. Verifying the combined signature is cheaper but
             * verifying the individual partial signatures has the advantage that it
             * can be used to determine which of the partial signatures are invalid
             * (if any), i.e., which of the partial signatures cause the combined
             * signature to be invalid and thus the protocol run to fail. It's also
             * fine to first verify the combined sig, and only verify the individual
             * sigs if it does not work.
             */
            if (!secp256k1_thresholdsig_partial_sig_verify(ctx, &musig_session[i], signer_data[i], N_SIGNERS, j, &partial_sig[j], &pubkeys[indices[j]])) {
                return 0;
            }
        }
    }
    return secp256k1_musig_partial_sig_combine(ctx, &musig_session[0], sig, partial_sig, N_SIGNERS);
}

int main(void) {
    secp256k1_context* ctx;
    int i;
    unsigned int j, k;
    unsigned char seckeys[N_SIGNERS_TOTAL][32];
    secp256k1_pubkey pubkeys[N_SIGNERS_TOTAL];
    secp256k1_pubkey signing_pubkeys[N_SIGNERS_TOTAL];
    secp256k1_thresholdsig_keyshard shards[N_SIGNERS_TOTAL][N_SIGNERS_TOTAL];
    secp256k1_pubkey pubcoeff[N_SIGNERS_TOTAL][N_SIGNERS];
    secp256k1_pubkey combined_pk;
    unsigned char msg[32] = "this_could_be_the_hash_of_a_msg!";
    unsigned char pk_hash[32];
    secp256k1_schnorrsig sig;
    unsigned char pkser[33];
    size_t pkserlen = sizeof(pkser);
    unsigned char sigser[64];
    size_t sigserlen = sizeof(sigser);

    /* Create a context for signing and verification */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    printf("{\n");
    for (i = 0; i < N_SIGNERS_TOTAL; i++) {
        if (!create_key(ctx, seckeys[i], &pubkeys[i])) {
            printf("FAILED\n");
            return 1;
        }
    }
    printf("\"pubKeys\": [\n");
    for (i = 0; i < N_SIGNERS_TOTAL; i++) {
        if (!secp256k1_ec_pubkey_serialize(ctx, pkser, &pkserlen, &pubkeys[i], SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        printf("  \"");
        for (j = 0; j < pkserlen; j++) {
            printf("%02x", pkser[j]);
        }
        printf("\",\n");
    }
    printf("],\n\"privKeys\":[\n");
    for (i = 0; i < N_SIGNERS_TOTAL; i++) {
        printf("  \"");
        for (j = 0; j < 32; j++) {
            printf("%02x", seckeys[i][j]);
        }
        printf("\",\n");
    }
    printf("],\n");
    if (!secp256k1_musig_pubkey_combine(ctx, NULL, &combined_pk, pk_hash, pubkeys, N_SIGNERS_TOTAL)) {
        printf("FAILED\n");
        return 1;
    }
    if (!secp256k1_ec_pubkey_serialize(ctx, pkser, &pkserlen, &combined_pk, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    printf("\"pubKeyCombined\": \"");
    for (j = 0; j < pkserlen; j++) {
        printf("%02x", pkser[j]);
    }
    printf("\",\n");
    
    printf("\"message\": \"");
    for (j = 0; j < 32; j++) {
        printf("%02x", msg[j]);
    }
    printf("\",\n");
    for (i = 0; i < N_SIGNERS_TOTAL; i++) {
        if (!secp256k1_thresholdsig_keysplit(ctx, shards[i], pubcoeff[i], seckeys[i], N_SIGNERS, N_SIGNERS_TOTAL)) {
            printf("FAILED\n");
            return 1;
        }
    }
    printf("],\n");
    printf("\"pubCoefficients\": [\n");
    for (i = 0; i < N_SIGNERS_TOTAL; i++) {
        printf("  [\n");
        for (j = 0; j < N_SIGNERS; j++) {
            if (!secp256k1_ec_pubkey_serialize(ctx, pkser, &pkserlen, &pubcoeff[i][j], SECP256K1_EC_COMPRESSED)) {
                return 0;
            }
            printf("    \"");
            for (k = 0; k < pkserlen; k++) {
                printf("%02x", pkser[k]);
            }
            printf("\",\n");
        }
        printf("  ],\n");
    }
    printf("],\n\"shards\":[\n");
    for (i = 0; i < N_SIGNERS_TOTAL; i++) {
        printf("  [\n");
        for (j = 0; j < N_SIGNERS_TOTAL; j++) {
            printf("     \"");
            for (k = 0; k < 32; k++) {
                printf("%02x", shards[i][j].data[k]);
            }
            printf("\",\n");
        }
        printf("  ],\n");
    }
    printf("],\n");
    for (i = 0; i < N_SIGNERS_TOTAL; i++) {
        size_t j2;
        /* Note that on every iteration, the inner loop will overwrite the `signing_pubkeys` array */
        for (j2 = 0; j2 < N_SIGNERS_TOTAL; j2++) {
            if (!secp256k1_thresholdsig_verify_shard(ctx, NULL, seckeys[i], signing_pubkeys, N_SIGNERS_TOTAL, pk_hash, j2 > 0, &shards[j2][i], i, j2, pubcoeff[j2], N_SIGNERS)) {
                printf("FAILED\n");
                return 1;
            }
        }
    }
    printf("\"modifiedPrivKeys\":[\n");
    for (i = 0; i < N_SIGNERS_TOTAL; i++) {
        printf("  \"");
        for (j = 0; j < 32; j++) {
            printf("%02x", seckeys[i][j]);
        }
        printf("\",\n");
    }
    printf("],\n");
    if (!sign(ctx, seckeys, &combined_pk, signing_pubkeys, msg, &sig)) {
        printf("FAILED\n");
        return 1;
    }
    if (!secp256k1_schnorrsig_serialize(ctx, sigser, &sig)) {
        return 0;
    }
    printf("\"signature\": \"");
    for (j = 0; j < sigserlen; j++) {
        printf("%02x", sigser[j]);
    }
    printf("\"\n},\n");
    if (!secp256k1_schnorrsig_verify(ctx, &sig, msg, &combined_pk)) {
        printf("FAILED\n");
        return 1;
    }
    secp256k1_context_destroy(ctx);
    return 0;
}

