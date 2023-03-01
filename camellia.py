# -*- coding: utf-8 -*-
"""
Created on Mon Dec 19 12:38:31 2022

@author: moham
"""

import os
def encrypte(msg, dh_mutual_key):
    camellia = Camellia(dh_mutual_key)
    c_msg = camellia.ecb_encrypt(msg)
    return c_msg

def decrypte(c_msg, dh_mutual_key):
    camellia = Camellia(dh_mutual_key,dec=True)
    msg = camellia.ecb_decrypt(c_msg)
    return msg.rstrip()
MASK8 = 0xFF
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
MASK128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
MASK192 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
MASK256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
C1 = 0xA09E667F3BCC908B
C2 = 0xB67AE8584CAA73B2
C3 = 0xC6EF372FE94F82BE
C4 = 0x54FF53A5F1D36F1C
C5 = 0x10E527FADE682D1D
C6 = 0xB05688C2B3E6C1FD

SBOX1 = [
    112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
    35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
    134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
    166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
    139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
    223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
    20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
    254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
    170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
    16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
    135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
    82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
    233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
    120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
    114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
    64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158
]
progress = 0


class Camellia:
    def __init__(self, key, dec=False):
        key = key.to_bytes(16, 'big') 
        self._key_size = len(key)
        if self._key_size not in [16, 24, 32]:  # Check if the size of the key is appropriate
            raise ValueError("Invalid Camellia key size. Key must be exactly 128/192/256 bits long.")
        self._key = int.from_bytes(key, byteorder='little')

        # The key is split into 2 64-bit parts KL and KR
        KL, KR = self._split_key(self._key)

        # Calculate 128-bit numbers KA and KB
        KA, KB = self._calculate_KA_KB(KL, KR)

        # Calculate auxiliary 64-bit keys kw1, ..., kw4, k1, ..., k24, ke1, ..., ke6 depending on the key size
        self._kw, self._k, self._kl = self._calculate_help_keys(KL, KR, KA, KB, dec)

    def encode_block(self, block):
        block = int.from_bytes(bytes(block, 'utf-8'), byteorder='little')

        # Encryption is performed according to the Feistel scheme with 18 stages for a 128 - bit key and 24 stages
        # for 192 - and 256 - bit keys. The FL and FLINV functions are applied every 6 steps.
        if self._key_size == 16:
            D1 = block >> 64  # The encrypted message is divided into two 64 - bit parts
            D2 = block & MASK64
            D1 = D1 ^ self._kw[0]  # Pre-whitening
            D2 = D2 ^ self._kw[1]
            D2 = D2 ^ self.F(D1, self._k[0])
            D1 = D1 ^ self.F(D2, self._k[1])
            D2 = D2 ^ self.F(D1, self._k[2])
            D1 = D1 ^ self.F(D2, self._k[3])
            D2 = D2 ^ self.F(D1, self._k[4])
            D1 = D1 ^ self.F(D2, self._k[5])
            D1 = self.FL(D1, self._kl[0])  # FL
            D2 = self.FLINV(D2, self._kl[1])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[6])
            D1 = D1 ^ self.F(D2, self._k[7])
            D2 = D2 ^ self.F(D1, self._k[8])
            D1 = D1 ^ self.F(D2, self._k[9])
            D2 = D2 ^ self.F(D1, self._k[10])
            D1 = D1 ^ self.F(D2, self._k[11])
            D1 = self.FL(D1, self._kl[2])  # FL
            D2 = self.FLINV(D2, self._kl[3])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[12])
            D1 = D1 ^ self.F(D2, self._k[13])
            D2 = D2 ^ self.F(D1, self._k[14])
            D1 = D1 ^ self.F(D2, self._k[15])
            D2 = D2 ^ self.F(D1, self._k[16])
            D1 = D1 ^ self.F(D2, self._k[17])
            D2 = D2 ^ self._kw[2]  # Final whitening
            D1 = D1 ^ self._kw[3]
            C = (D2 << 64) | D1
        else:
            D1 = block >> 64  # The encrypted message is split into two 64-bit parts
            D2 = block & MASK64
            D1 = D1 ^ self._kw[0]  # Pre-whitening
            D2 = D2 ^ self._kw[1]
            D2 = D2 ^ self.F(D1, self._k[0])
            D1 = D1 ^ self.F(D2, self._k[1])
            D2 = D2 ^ self.F(D1, self._k[2])
            D1 = D1 ^ self.F(D2, self._k[3])
            D2 = D2 ^ self.F(D1, self._k[4])
            D1 = D1 ^ self.F(D2, self._k[5])
            D1 = self.FL(D1, self._kl[0])  # FL
            D2 = self.FLINV(D2, self._kl[1])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[6])
            D1 = D1 ^ self.F(D2, self._k[7])
            D2 = D2 ^ self.F(D1, self._k[8])
            D1 = D1 ^ self.F(D2, self._k[9])
            D2 = D2 ^ self.F(D1, self._k[10])
            D1 = D1 ^ self.F(D2, self._k[11])
            D1 = self.FL(D1, self._kl[2])  # FL
            D2 = self.FLINV(D2, self._kl[3])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[12])
            D1 = D1 ^ self.F(D2, self._k[13])
            D2 = D2 ^ self.F(D1, self._k[14])
            D1 = D1 ^ self.F(D2, self._k[15])
            D2 = D2 ^ self.F(D1, self._k[16])
            D1 = D1 ^ self.F(D2, self._k[17])
            D1 = self.FL(D1, self._kl[4])  # FL
            D2 = self.FLINV(D2, self._kl[5])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[18])
            D1 = D1 ^ self.F(D2, self._k[19])
            D2 = D2 ^ self.F(D1, self._k[20])
            D1 = D1 ^ self.F(D2, self._k[21])
            D2 = D2 ^ self.F(D1, self._k[22])
            D1 = D1 ^ self.F(D2, self._k[23])
            D2 = D2 ^ self._kw[2]  # Final whitening
            D1 = D1 ^ self._kw[3]
            C = (D2 << 64) | D1
            
        value=b''
        str_val=str(C)
        byte_val = str_val.encode()
        value =C.to_bytes(self._key_size, byteorder='little')
        return value

    def decode_block(self, block):
        block = int.from_bytes(block, byteorder='little')

        if self._key_size == 16:
            D1 = block >> 64  # The encrypted message is divided into two 64 - bit parts
            D2 = block & MASK64
            D1 = D1 ^ self._kw[0]  # Pre-whitening
            D2 = D2 ^ self._kw[1]
            D2 = D2 ^ self.F(D1, self._k[0])#1
            D1 = D1 ^ self.F(D2, self._k[1])
            D2 = D2 ^ self.F(D1, self._k[2])
            D1 = D1 ^ self.F(D2, self._k[3])
            D2 = D2 ^ self.F(D1, self._k[4])
            D1 = D1 ^ self.F(D2, self._k[5])
            D1 = self.FL(D1, self._kl[0])  # FL
            D2 = self.FLINV(D2, self._kl[1])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[6])
            D1 = D1 ^ self.F(D2, self._k[7])
            D2 = D2 ^ self.F(D1, self._k[8])
            D1 = D1 ^ self.F(D2, self._k[9])
            D2 = D2 ^ self.F(D1, self._k[10])
            D1 = D1 ^ self.F(D2, self._k[11])
            D1 = self.FL(D1, self._kl[2])  # FL
            D2 = self.FLINV(D2, self._kl[3])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[12])
            D1 = D1 ^ self.F(D2, self._k[13])
            D2 = D2 ^ self.F(D1, self._k[14])
            D1 = D1 ^ self.F(D2, self._k[15])
            D2 = D2 ^ self.F(D1, self._k[16])
            D1 = D1 ^ self.F(D2, self._k[17])
            D2 = D2 ^ self._kw[2]  # Final whitening
            D1 = D1 ^ self._kw[3]
            C = (D2 << 64) | D1
        else:
            D1 = block >> 64  # The encrypted message is split into two 64-bit parts
            D2 = block & MASK64
            D1 = D1 ^ self._kw[0]  # Pre-whitening
            D2 = D2 ^ self._kw[1]
            D2 = D2 ^ self.F(D1, self._k[0])
            D1 = D1 ^ self.F(D2, self._k[1])
            D2 = D2 ^ self.F(D1, self._k[2])
            D1 = D1 ^ self.F(D2, self._k[3])
            D2 = D2 ^ self.F(D1, self._k[4])
            D1 = D1 ^ self.F(D2, self._k[5])
            D1 = self.FL(D1, self._kl[0])  # FL
            D2 = self.FLINV(D2, self._kl[1])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[6])
            D1 = D1 ^ self.F(D2, self._k[7])
            D2 = D2 ^ self.F(D1, self._k[8])
            D1 = D1 ^ self.F(D2, self._k[9])
            D2 = D2 ^ self.F(D1, self._k[10])
            D1 = D1 ^ self.F(D2, self._k[11])
            D1 = self.FL(D1, self._kl[2])  # FL
            D2 = self.FLINV(D2, self._kl[3])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[12])
            D1 = D1 ^ self.F(D2, self._k[13])
            D2 = D2 ^ self.F(D1, self._k[14])
            D1 = D1 ^ self.F(D2, self._k[15])
            D2 = D2 ^ self.F(D1, self._k[16])
            D1 = D1 ^ self.F(D2, self._k[17])
            D1 = self.FL(D1, self._kl[4])  # FL
            D2 = self.FLINV(D2, self._kl[5])  # FLINV
            D2 = D2 ^ self.F(D1, self._k[18])
            D1 = D1 ^ self.F(D2, self._k[19])
            D2 = D2 ^ self.F(D1, self._k[20])
            D1 = D1 ^ self.F(D2, self._k[21])
            D2 = D2 ^ self.F(D1, self._k[22])
            D1 = D1 ^ self.F(D2, self._k[23])
            D2 = D2 ^ self._kw[2]
            D1 = D1 ^ self._kw[3]
            C = (D2 << 64) | D1

        value=b''
        str_val=str(C)
        byte_val = str_val.encode()
        value =C.to_bytes(self._key_size, byteorder='little')
        return value

    def _split_key(self, key):
        if self._key_size == 16:
            return key, 0
        elif self._key_size == 24:
            return key >> 64, (((key & MASK64) << 64) | (~(key & MASK64))) & MASK128
        return key >> 128, key & MASK128

    # We calculate the 128-bit numbers KA and KB. Variables D1 and D2 are 64-bit.
    def _calculate_KA_KB(self, KL, KR):
        D1 = (KL ^ KR) >> 64
        D2 = (KL ^ KR) & MASK64
        D2 = D2 ^ self.F(D1, C1)
        D1 = D1 ^ self.F(D2, C2)
        D1 = D1 ^ (KL >> 64)
        D2 = D2 ^ (KL & MASK64)
        D2 = D2 ^ self.F(D1, C3)
        D1 = D1 ^ self.F(D2, C4)
        KA = ((D1 << 64) & MASK128)|D2
        D1 = (KA ^ KR) >> 64
        D2 = (KA ^ KR) & MASK64
        D2 = D2 ^ self.F(D1, C5)
        D1 = D1 ^ self.F(D2, C6)
        KB = ((D1 << 64) & MASK128) | D2
        return KA, KB

    def _calculate_help_keys(self, KL, KR, KA, KB, dec=False):
        if self._key_size == 16:
            kw = [0] * 4
            k = [0] * 18
            kl = [0] * 4

            kw[0] = self.shift(KL, 0, 128) >> 64
            kw[1] = self.shift(KL, 0, 128) & MASK64
            k[0] = self.shift(KA, 0, 128) >> 64
            k[1] = self.shift(KA, 0, 128) & MASK64
            k[2] = self.shift(KL, 15, 128) >> 64
            k[3] = self.shift(KL, 15, 128) & MASK64
            k[4] = self.shift(KA, 15, 128) >> 64
            k[5] = self.shift(KA, 15, 128) & MASK64
            kl[0] = self.shift(KA, 30, 128) >> 64
            kl[1] = self.shift(KA, 30, 128) & MASK64
            k[6] = self.shift(KL, 45, 128) >> 64
            k[7] = self.shift(KL, 45, 128) & MASK64
            k[8] = self.shift(KA, 45, 128) >> 64
            k[9] = self.shift(KL, 60, 128) & MASK64
            k[10] = self.shift(KA, 60, 128) >> 64
            k[11] = self.shift(KA, 60, 128) & MASK64
            kl[2] = self.shift(KL, 77, 128) >> 64
            kl[3] = self.shift(KL, 77, 128) & MASK64
            k[12] = self.shift(KL, 94, 128) >> 64
            k[13] = self.shift(KL, 94, 128) & MASK64
            k[14] = self.shift(KA, 94, 128) >> 64
            k[15] = self.shift(KA, 94, 128) & MASK64
            k[16] = self.shift(KL, 111, 128) >> 64
            k[17] = self.shift(KL, 111, 128) & MASK64
            kw[2] = self.shift(KA, 111, 128) >> 64
            kw[3] = self.shift(KA, 111, 128) & MASK64
            if dec:
                # swap
                kw[0], kw[2] = kw[2], kw[0]
                kw[1], kw[3] = kw[3], kw[1]
                k[0], k[17] = k[17], k[0]
                k[1], k[16] = k[16], k[1]
                k[2], k[15] = k[15], k[2]
                k[3], k[14] = k[14], k[3]
                k[4], k[13] = k[13], k[4]
                k[5], k[12] = k[12], k[5]
                k[6], k[11] = k[11], k[6]
                k[7], k[10] = k[10], k[7]
                k[8], k[9] = k[9], k[8]
                kl[0], kl[3] = kl[3], kl[0]
                kl[1], kl[2] = kl[2], kl[1]
        else:
            kw = [0] * 4
            k = [0] * 24
            kl = [0] * 6

            kw[0] = self.shift(KL, 0, 128) >> 64
            kw[1] = self.shift(KL, 0, 128) & MASK64
            k[0] = self.shift(KB, 0, 128) >> 64
            k[1] = self.shift(KB, 0, 128) & MASK64
            k[2] = self.shift(KR, 15, 128) >> 64
            k[3] = self.shift(KR, 15, 128) & MASK64
            k[4] = self.shift(KA, 15, 128) >> 64
            k[5] = self.shift(KA, 15, 128) & MASK64
            kl[0] = self.shift(KR, 30, 128) >> 64
            kl[1] = self.shift(KR, 30, 128) & MASK64
            k[6] = self.shift(KB, 30, 128) >> 64
            k[7] = self.shift(KB, 30, 128) & MASK64
            k[8] = self.shift(KL, 45, 128) >> 64
            k[9] = self.shift(KL, 45, 128) & MASK64
            k[10] = self.shift(KA, 45, 128) >> 64
            k[11] = self.shift(KA, 45, 128) & MASK64
            kl[2] = self.shift(KL, 60, 128) >> 64
            kl[3] = self.shift(KL, 60, 128) & MASK64
            k[12] = self.shift(KR, 60, 128) >> 64
            k[13] = self.shift(KR, 60, 128) & MASK64
            k[14] = self.shift(KB, 60, 128) >> 64
            k[15] = self.shift(KB, 60, 128) & MASK64
            k[16] = self.shift(KL, 77, 128) >> 64
            k[17] = self.shift(KL, 77, 128) & MASK64
            kl[4] = self.shift(KA, 77, 128) >> 64
            kl[5] = self.shift(KA, 77, 128) & MASK64
            k[18] = self.shift(KR, 94, 128) >> 64
            k[19] = self.shift(KR, 94, 128) & MASK64
            k[20] = self.shift(KA, 94, 128) >> 64
            k[21] = self.shift(KA, 94, 128) & MASK64
            k[22] = self.shift(KL, 111, 128) >> 64
            k[23] = self.shift(KL, 111, 128) & MASK64
            kw[2] = self.shift(KB, 111, 128) >> 64
            kw[3] = self.shift(KB, 111, 128) & MASK64
            if dec:
                # swap
                kw[0], kw[2] = kw[2], kw[0]
                kw[1], kw[3] = kw[3], kw[1]
                k[0], k[23] = k[23], k[0]
                k[1], k[22] = k[22], k[1]
                k[2], k[21] = k[21], k[2]
                k[3], k[20] = k[20], k[3]
                k[4], k[19] = k[19], k[4]
                k[5], k[18] = k[18], k[5]
                k[6], k[17] = k[17], k[6]
                k[7], k[16] = k[16], k[7]
                k[8], k[15] = k[15], k[8]
                k[9], k[14] = k[14], k[9]
                k[10], k[13] = k[13], k[10]
                k[11], k[12] = k[12], k[11]
                kl[0], kl[5] = kl[5], kl[0]
                kl[1], kl[4] = kl[4], kl[1]
                kl[2], kl[3] = kl[3], kl[2]
        return kw, k, kl

    def shift(self, num, shift, num_size):
        shift %= num_size
        return ((num << shift) | (num >> (num_size - shift))) & ((1 << num_size) - 1)

    # Secondary functions
    def F(self, F_IN, KE):

        x = F_IN ^ KE
        t1 = (x >> 56) & MASK8
        t2 = (x >> 48) & MASK8
        t3 = (x >> 40) & MASK8
        t4 = (x >> 32) & MASK8
        t5 = (x >> 24) & MASK8
        t6 = (x >> 16) & MASK8
        t7 = (x >> 8) & MASK8
        t8 = x & MASK8
        t1 = SBOX1[t1]
        t2 = self.shift(SBOX1[t2], 1, 8)
        t3 = self.shift(SBOX1[t3], 7, 8)
        t4 = SBOX1[self.shift(t4, 1, 8)]
        t5 = self.shift(SBOX1[t5], 1, 8)
        t6 = self.shift(SBOX1[t6], 7, 8)
        t7 = SBOX1[self.shift(t7, 1, 8)]
        t8 = SBOX1[t8]
        y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
        y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
        y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
        y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
        y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
        y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
        y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
        y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
        F_OUT = (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) | (y5 << 24) | (y6 << 16) | (y7 << 8) | y8

        return F_OUT

    def FL(self, FL_IN, KE):
        x1 = FL_IN >> 32
        x2 = FL_IN & MASK32
        k1 = KE >> 32
        k2 = KE & MASK32
        x2 = x2 ^ self.shift(x1 & k1, 1, 32)
        x1 = x1 ^ (x2 | k2)
        FL_OUT = (x1 << 32) | x2

        return FL_OUT

    def FLINV(self, FLINV_IN, KE):
        y1 = FLINV_IN >> 32
        y2 = FLINV_IN & MASK32
        k1 = KE >> 32
        k2 = KE & MASK32
        y1 = y1 ^ (y2 | k2)
        y2 = y2 ^ self.shift(y1 & k1, 1, 32)
        FLINV_OUT = (y1 << 32) | y2

        return FLINV_OUT


# OFB mode of operation, encrypt large messages built of more then one block
    def ecb_encrypt(self, data):
     data = self._pad_data(data)
     encrypted_data = b''
     for i in range(0, len(data), 16):
          encrypted_data += self.encode_block(data[i:i+16])
     return encrypted_data

    def ecb_decrypt(self, data):
     decrypted_data = b''
     for i in range(0, len(data), 16):
        decrypted_data += self.decode_block(data[i:i+16])
     st=self._unpad_data(decrypted_data)
     return st

    def _pad_data(self, data): #add zero's
      padding_length = 16 - (len(data) % 16)
      return data + bytes([padding_length] * padding_length).decode('utf-8')

    def _unpad_data(self, data): #remove zero's
      padding_length = data[-1]
      return data[:-padding_length]
 
    