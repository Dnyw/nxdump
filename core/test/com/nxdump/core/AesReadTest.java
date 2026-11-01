package com.nxdump.core;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Regression test: optimized random-access CTR output must match the JCE reference byte-for-byte. */
public final class AesReadTest {
    private static final int CHUNK = 2 << 20;

    public static void main(String[] args) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16];
        byte[] upper = new byte[16];
        byte[] rawBytes = new byte[CHUNK + 16384];
        random.nextBytes(key);
        random.nextBytes(upper);
        random.nextBytes(rawBytes);
        // The real NCA section start is sector aligned; include non-block-aligned read positions.
        long sectionStart = 0x2400L;
        Source raw = new Source.Bytes(rawBytes);
        int[][] cases = {
            {0, 1}, {1, 31}, {15, 64}, {16, 257},
            {CHUNK - 31, 128}, {CHUNK - 7, 4096},
            {CHUNK + 3, 8191}
        };
        for (int[] test : cases) {
            int pos = test[0], len = test[1];
            byte[] actual = new byte[len];
            byte[] expected = reference(rawBytes, key, upper, sectionStart, pos, len);
            Aes.ctrRead(raw, key, upper, sectionStart, pos, actual, 0, len);
            if (!Arrays.equals(expected, actual))
                throw new AssertionError("AES-CTR mismatch at pos=" + pos + " len=" + len);
        }
        System.out.println("AES-CTR byte-exact tests passed");
    }

    private static byte[] reference(byte[] raw, byte[] key, byte[] upper, long sectionStart,
                                     int pos, int len) throws Exception {
        long absolute = sectionStart + pos;
        int prefix = (int) (absolute & 15);
        byte[] input = Arrays.copyOfRange(raw, pos - prefix, pos + len);
        byte[] iv = upper.clone();
        Bin.putBe64(iv, 8, (absolute - prefix) >>> 4);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] decrypted = cipher.doFinal(input);
        return Arrays.copyOfRange(decrypted, prefix, prefix + len);
    }
}
