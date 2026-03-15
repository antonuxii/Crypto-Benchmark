// FEAL implementation taken from https://gist.github.com/odzhan/f0cb8657060199b93540f710f4883485 full credit goes to the author odzhan.
// Only added decryption function

//
// FEAL-N Block Cipher (N is the number of rounds). Up to 32 rounds
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

// Define the Sd function as per equation (7.6)
uint8_t Sd(uint8_t x, uint8_t y, uint8_t d) {
    uint16_t sum = x + y + d;  // Sum could be up to 0x1FE
    uint8_t s = sum & 0xFF;    // Ignore the carry out of the top bit (mod 256)
    // Left rotate the result by 2 bits
    return ((s << 2) | (s >> 6)) & 0xFF;
}

// Define S0 and S1 functions
uint8_t S0(uint8_t x, uint8_t y) {
    return Sd(x, y, 0);
}

uint8_t S1(uint8_t x, uint8_t y) {
    return Sd(x, y, 1);
}

// Implement the fK function as per Table 7.9 for key schedule
uint32_t fK(uint32_t A, uint32_t B) {
    // Extract bytes A0, A1, A2, A3 from A
    uint8_t A0 = (A >> 24) & 0xFF;
    uint8_t A1 = (A >> 16) & 0xFF;
    uint8_t A2 = (A >> 8)  & 0xFF;
    uint8_t A3 = A & 0xFF;

    // Extract bytes B0, B1, B2, B3 from B
    uint8_t B0 = (B >> 24) & 0xFF;
    uint8_t B1 = (B >> 16) & 0xFF;
    uint8_t B2 = (B >> 8)  & 0xFF;
    uint8_t B3 = B & 0xFF;

    // Compute intermediate values
    uint8_t t1 = A0 ^ A1;
    uint8_t t2 = A2 ^ A3;

    // Compute U components
    uint8_t U1 = S1(t1, t2 ^ B0);
    uint8_t U2 = S0(t2, U1 ^ B1);
    uint8_t U0 = S0(A0, U1 ^ B2);
    uint8_t U3 = S1(A3, U2 ^ B3);

    // Combine U0, U1, U2, U3 into a 32-bit word
    uint32_t U = ((uint32_t)U0 << 24) | ((uint32_t)U1 << 16) | ((uint32_t)U2 << 8) | U3;

    return U;
}

// Implement the f function as per Table 7.9 for encryption
uint32_t f(uint32_t A, uint16_t Y) {
    // Extract bytes A0, A1, A2, A3 from A
    uint8_t A0 = (A >> 24) & 0xFF;
    uint8_t A1 = (A >> 16) & 0xFF;
    uint8_t A2 = (A >> 8)  & 0xFF;
    uint8_t A3 = A & 0xFF;

    // Extract bytes Y0, Y1 from Y
    uint8_t Y0 = (Y >> 8) & 0xFF;
    uint8_t Y1 = Y & 0xFF;

    // Compute intermediate values
    uint8_t t1 = (A0 ^ A1) ^ Y0;
    uint8_t t2 = (A2 ^ A3) ^ Y1;

    // Compute output components
    uint8_t F1 = S1(t1, t2);
    uint8_t F2 = S0(t2, F1);
    uint8_t F0 = S0(A0, F1);
    uint8_t F3 = S1(A3, F2);

    // Combine F0, F1, F2, F3 into a 32-bit word
    uint32_t F = ((uint32_t)F0 << 24) | ((uint32_t)F1 << 16) | ((uint32_t)F2 << 8) | F3;

    return F;
}

// Key schedule: Compute N + 8 sixteen-bit subkeys Ki from 64-bit key K
void key_schedule(uint64_t K, uint16_t *Ki, int N) {
    int total_subkeys = N + 8;
    int num_U_values = (N / 2) + 4 + 2; // U(-2) to U((N/2)+3)
    uint32_t *U = malloc(num_U_values * sizeof(uint32_t)); // Dynamic allocation for U array
    int i;

    // Initialize U(-2), U(-1), U(0)
    U[0] = 0;                             // U(-2) = 0
    U[1] = (uint32_t)(K >> 32);           // U(-1) = k1...k32 (first 32 bits of K)
    U[2] = (uint32_t)(K & 0xFFFFFFFF);    // U(0) = k33...k64 (last 32 bits of K)

    // Key extension loop
    for (i = 1; i <= (N / 2) + 4; i++) {
        uint32_t temp = U[i + 1] ^ U[i - 1];  // U(i−1) ⊕ U(i−3)
        U[i + 2] = fK(U[i], temp);            // U(i) ← fK(U(i−2), temp)

        // Extract U0, U1, U2, U3 from U[i + 2]
        uint8_t U0 = (U[i + 2] >> 24) & 0xFF;
        uint8_t U1 = (U[i + 2] >> 16) & 0xFF;
        uint8_t U2 = (U[i + 2] >> 8)  & 0xFF;
        uint8_t U3 = U[i + 2] & 0xFF;

        // Compute subkeys Ki
        Ki[2 * i - 2] = ((uint16_t)U0 << 8) | U1; // K2i−2 = (U0, U1)
        Ki[2 * i - 1] = ((uint16_t)U2 << 8) | U3; // K2i−1 = (U2, U3)
    }

    free(U);
}

// Encryption function for FEAL-N
uint64_t encrypt(uint64_t M, uint16_t *Ki, int N) {
    uint32_t *L = malloc((N + 1) * sizeof(uint32_t));
    uint32_t *R = malloc((N + 1) * sizeof(uint32_t));
    int i;

    // Divide plaintext M into ML and MR
    uint32_t ML = (uint32_t)(M >> 32);
    uint32_t MR = (uint32_t)(M & 0xFFFFFFFF);

    // Step 3: XOR initial subkeys
    L[0] = ML ^ (((uint32_t)Ki[N] << 16) | Ki[N + 1]);       // (KN, KN+1)
    R[0] = MR ^ (((uint32_t)Ki[N + 2] << 16) | Ki[N + 3]);   // (KN+2, KN+3)

    // Step 4: R0 ← R0⊕L0
    R[0] = R[0] ^ L[0];

    // Feistel rounds
    for (i = 1; i <= N; i++) {
        L[i] = R[i - 1];
        uint32_t temp = f(R[i - 1], Ki[i - 1]);  // Ki−1
        R[i] = L[i - 1] ^ temp;
    }

    // Step 6: L_N ← L_N⊕R_N
    L[N] = L[N] ^ R[N];

    // Step 7: XOR final subkeys
    R[N] = R[N] ^ (((uint32_t)Ki[N + 4] << 16) | Ki[N + 5]);   // (KN+4, KN+5)
    L[N] = L[N] ^ (((uint32_t)Ki[N + 6] << 16) | Ki[N + 7]);   // (KN+6, KN+7)

    // Step 8: C ← (R_N, L_N) (Note the order is exchanged)
    uint64_t C = ((uint64_t)R[N] << 32) | L[N];

    free(L);
    free(R);

    return C;
}

// Decryption function for FEAL-N
uint64_t decrypt(uint64_t C, uint16_t *Ki, int N) {
    uint32_t *L = malloc((N + 1) * sizeof(uint32_t));
    uint32_t *R = malloc((N + 1) * sizeof(uint32_t));
    int i;

    // Divide ciphertext C into CR and CL (note: C is stored as (R_N, L_N))
    uint32_t CR = (uint32_t)(C >> 32);
    uint32_t CL = (uint32_t)(C & 0xFFFFFFFF);

    // Step 1: Undo final subkey XOR
    CR = CR ^ (((uint32_t)Ki[N + 4] << 16) | Ki[N + 5]);   // (KN+4, KN+5)
    CL = CL ^ (((uint32_t)Ki[N + 6] << 16) | Ki[N + 7]);   // (KN+6, KN+7)

    // Step 2: Undo L_N ← L_N⊕R_N
    CL = CL ^ CR;

    // Initialize from ciphertext
    L[N] = CL;
    R[N] = CR;

    // Step 3: Inverse Feistel rounds (apply in reverse order)
    // In encryption: L[i] = R[i-1] and R[i] = L[i-1] ^ f(R[i-1], Ki[i-1])
    // To reverse: R[i-1] = L[i] and L[i-1] = R[i] ^ f(L[i], Ki[i-1])
    for (i = N; i >= 1; i--) {
        uint32_t temp = f(L[i], Ki[i - 1]);  // Use same key Ki-1
        uint32_t newR = L[i];
        uint32_t newL = R[i] ^ temp;
        L[i - 1] = newL;
        R[i - 1] = newR;
    }

    // Step 4: Undo R0 ← R0⊕L0
    R[0] = R[0] ^ L[0];

    // Step 5: Undo initial subkey XOR
    L[0] = L[0] ^ (((uint32_t)Ki[N] << 16) | Ki[N + 1]);       // (KN, KN+1)
    R[0] = R[0] ^ (((uint32_t)Ki[N + 2] << 16) | Ki[N + 3]);   // (KN+2, KN+3)

    // Step 6: M ← (L_0, R_0)
    uint64_t M = ((uint64_t)L[0] << 32) | R[0];

    free(L);
    free(R);

    return M;
}

int main() {
    uint64_t K;         // 64-bit key input
    uint64_t M;         // 64-bit plaintext input
    uint64_t C;         // 64-bit ciphertext output
    uint16_t *Ki;       // Subkeys Ki
    int i;
    int N;              // Number of rounds

    // Set the number of rounds (must be even)
    N = 16; // Example: FEAL-16

    // Calculate the total number of subkeys needed
    int total_subkeys = N + 8;

    // Allocate memory for subkeys
    Ki = malloc(total_subkeys * sizeof(uint16_t));

    // Example 64-bit key and plaintext (you can modify these as needed)
    K = 0x0000000000000000;
    M = 0xffffffffffffffff;

    // Compute subkeys
    key_schedule(K, Ki, N);

    // Display subkeys
    printf("Subkeys Ki:\n");
    for (i = 0; i < total_subkeys; i++) {
        printf("K%d: %04X\n", i, Ki[i]);
    }
    printf("\n");

    // Encrypt plaintext
    C = encrypt(M, Ki, N);

    // Display plaintext and ciphertext
    printf("Plaintext M: %016llX\n", M);
    printf("Ciphertext C: %016llX\n", C);

    // Decrypt ciphertext
    uint64_t M_decrypted = decrypt(C, Ki, N);

    // Display decrypted plaintext
    printf("Decrypted M: %016llX\n", M_decrypted);

    // Verify decryption
    if (M == M_decrypted) {
        printf("\n[SUCCESS] Decryption verified! Plaintext matches decrypted ciphertext.\n");
    } else {
        printf("\n[FAILED] Decryption mismatch! Plaintext does not match decrypted ciphertext.\n");
    }

    // Clean up
    free(Ki);

    return 0;
}