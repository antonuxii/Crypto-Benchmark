// Just a test script to compare outputs of our Serpent.py implementation against a standard library
// Probably remove it later

#include <stdio.h>
#include <string.h>
#include <gcrypt.h>

static void die(const char *msg, gcry_error_t err) {
    fprintf(stderr, "%s: %s\n", msg, gcry_strerror(err));
    return;
}

int main(void) {
    // Initialize libgcrypt
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        return 1;
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    // Open Serpent-128 in ECB mode
    gcry_cipher_hd_t hd;
    gcry_error_t err = gcry_cipher_open(
        &hd,
        GCRY_CIPHER_SERPENT128,
        GCRY_CIPHER_MODE_ECB,
        0
    );
    if (err) die("cipher_open", err);

    // 128-bit zero key
    unsigned char key[16] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    err = gcry_cipher_setkey(hd, key, sizeof(key));
    if (err) die("setkey", err);

    // 128-bit zero plaintext
    unsigned char plaintext[16] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    unsigned char ciphertext[16];

    err = gcry_cipher_encrypt(
        hd,
        ciphertext, sizeof(ciphertext),
        plaintext, sizeof(plaintext)
    );
    if (err) die("encrypt", err);

    // Print ciphertext
    printf("Ciphertext: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    gcry_cipher_close(hd);
    return 0;
}
