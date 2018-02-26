package com.virgilsecurity.virgilsamples;

import android.test.AndroidTestCase;

import com.virgilsecurity.crypto.VirgilHash;
import com.virgilsecurity.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.KeysType;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;

/**
 * Created by Andrii Iakovenko, Danylo Oliinyk on 07.10.16 at Virgil Security.
 * -__o
 */
public class CryptoTest extends AndroidTestCase {

    private static final String TEXT = "This text is used for unit tests";
    private static final String PASSWORD = "ThisIsPassWoRd2016";
    private static final byte[] INVALID_SIGNATURE = new byte[]{48, 88, 48, 13, 6, 9, 96, -122, 72, 1, 101, 3, 4, 2, 2,
            5, 0, 4, 71, 48, 69, 2, 33, 0, -108, -6, -82, 29, -38, 103, -13, 42, 101, 76, -34, -53, -96, -70, 85, 80, 0,
            88, 77, 48, 9, -100, 81, 39, -51, -125, -102, -107, -108, 14, -88, 7, 2, 32, 13, -71, -99, 8, -69, -77, 30,
            98, 20, -25, 60, 125, -19, 67, 12, -30, 65, 93, -29, -92, -58, -91, 91, 50, -111, -79, 50, -123, -39, 36,
            48, -20};
    private static final int MAX_RECIPIENTS = 100;

    private VirgilCrypto crypto;

    @Override
    protected void setUp() throws Exception {
        crypto = new VirgilCrypto();
    }

    public void testCreateVirgilHash() {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            VirgilHash hash = VirgilCrypto.createVirgilHash(algorithm);
            assertNotNull(hash);
        }
    }

    public void testToVirgilKeyPairType() {
        for (KeysType keysType : KeysType.values()) {
            VirgilKeyPair.Type type = VirgilCrypto.toVirgilKeyPairType(keysType);
            assertNotNull(type);
        }
    }

    public void testCalculateFingerprint_null() throws CryptoException {
        try {
            crypto.generateHash(null);
        } catch (NullArgumentException e) {
            return;
        }
        fail();
    }

    public void testCalculateFingerprint() throws CryptoException {
        byte[] fingerprint = crypto.generateHash(TEXT.getBytes());
        assertNotNull(fingerprint);
        assertTrue(fingerprint.length > 0);
    }

    public void testComputeHash_nullData() {
        try {
            crypto.generateHash(null, HashAlgorithm.MD5);
        } catch (NullArgumentException e) {
            return;
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        fail();
    }

    public void testComputeHash() {
        try {
            for (HashAlgorithm algorithm : HashAlgorithm.values()) {
                byte[] hash = crypto.generateHash(null, algorithm);

                assertNotNull(hash);
                assertTrue(hash.length > 0);
            }
        } catch (NullArgumentException e) {
            return;
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        fail();
    }

    public void testDecrypt() throws CryptoException {
        List<VirgilPrivateKey> privateKeys = new ArrayList<>();
        List<VirgilPublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < MAX_RECIPIENTS; i++) {
            com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
            privateKeys.add(keyPair.getPrivateKey());
            recipients.add(keyPair.getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);
        for (VirgilPrivateKey privateKey : privateKeys) {
            byte[] decrypted = crypto.decrypt(encrypted, privateKey);
            assertArrayEquals(TEXT.getBytes(), decrypted);
        }
    }

    public void testDecrypt_stream() throws IOException, CryptoException {
        List<VirgilPrivateKey> privateKeys = new ArrayList<>();
        List<VirgilPublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < MAX_RECIPIENTS; i++) {
            com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
            privateKeys.add(keyPair.getPrivateKey());
            recipients.add(keyPair.getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);
        for (VirgilPrivateKey privateKey : privateKeys) {
            try (InputStream is = new ByteArrayInputStream(encrypted);
                     ByteArrayOutputStream os = new ByteArrayOutputStream()) {
                crypto.decrypt(is, os, privateKey);

                byte[] decrypted = os.toByteArray();

                assertArrayEquals(TEXT.getBytes(), decrypted);
            }
        }
    }

    public void testEncrypt() throws CryptoException {
        List<VirgilPublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < MAX_RECIPIENTS; i++) {
            recipients.add(crypto.generateKeys().getPublicKey());
        }
        crypto.encrypt(TEXT.getBytes(StandardCharsets.UTF_8), crypto.generateKeys().getPublicKey());
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients);

        assertNotNull(encrypted);
    }

    public void testEncrypt_noRecipients_success() throws EncryptionException {
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), Collections.<VirgilPublicKey>emptyList());

        assertNotNull(encrypted);
    }

    public void testEncrypt_stream() throws IOException, CryptoException {
        List<VirgilPublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < MAX_RECIPIENTS; i++) {
            recipients.add(crypto.generateKeys().getPublicKey());
        }
        try (OutputStream os = new ByteArrayOutputStream()) {
            crypto.encrypt(new ByteArrayInputStream(TEXT.getBytes()), os, recipients);
        }
    }

    public void testExportPrivateKey() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey(), null);

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    public void testExportPrivateKey_withPassword() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    public void testExportPublicKey() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();

        byte[] key = crypto.exportPublicKey(keyPair.getPublicKey());

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    public void testExtractPublicKey() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();

        PublicKey publicKey = crypto.extractPublicKey(keyPair.getPrivateKey());
        assertNotNull(publicKey);
        assertArrayEquals(keyPair.getPublicKey().getIdentifier(), ((VirgilPublicKey) publicKey).getIdentifier());
        assertArrayEquals(keyPair.getPublicKey().getRawKey(), ((VirgilPublicKey) publicKey).getRawKey());
    }

    public void testGenerateKeys() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();

        assertNotNull(keyPair);

        VirgilPublicKey publicKey = keyPair.getPublicKey();
        assertNotNull(publicKey);
        assertNotNull(publicKey.getIdentifier());
        assertNotNull(publicKey.getRawKey());

        VirgilPrivateKey privateKey = keyPair.getPrivateKey();
        assertNotNull(privateKey);
        assertNotNull(privateKey.getIdentifier());
        assertNotNull(privateKey.getRawKey());
    }

    public void testImportPrivateKey() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();

        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), null);

        VirgilPrivateKey importedKey = crypto.importPrivateKey(keyData);

        assertNotNull(importedKey);
        assertNotNull(importedKey.getIdentifier());
        assertNotNull(importedKey.getRawKey());
        assertArrayEquals(keyPair.getPrivateKey().getIdentifier(), importedKey.getIdentifier());
        assertArrayEquals(keyPair.getPrivateKey().getRawKey(), importedKey.getRawKey());
    }

    public void testImportPrivateKey_withPassword() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        VirgilPrivateKey importedKey = crypto.importPrivateKey(keyData, PASSWORD);

        assertNotNull(importedKey);
        assertNotNull(importedKey.getIdentifier());
        assertNotNull(importedKey.getRawKey());
        assertArrayEquals(keyPair.getPrivateKey().getIdentifier(), importedKey.getIdentifier());
        assertArrayEquals(keyPair.getPrivateKey().getRawKey(), importedKey.getRawKey());
    }

    public void testImportPrivateKey_withWrongPassword() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        try {
            crypto.importPrivateKey(keyData, PASSWORD + "1");
        } catch (CryptoException e) {
            return;
        }
        fail();
    }

    public void testImportPublicKey() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();

        byte[] keyData = crypto.exportPublicKey(keyPair.getPublicKey());
        VirgilPublicKey publicKey = crypto.importPublicKey(keyData);

        assertNotNull(publicKey);
        assertNotNull(publicKey.getIdentifier());
        assertNotNull(publicKey.getRawKey());
        assertArrayEquals(keyPair.getPublicKey().getIdentifier(), publicKey.getIdentifier());
        assertArrayEquals(keyPair.getPublicKey().getRawKey(), publicKey.getRawKey());
    }

    public void testSign_nullData() {
        try {
            com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
            crypto.generateSignature((byte[]) null, keyPair.getPrivateKey());
        } catch (NullArgumentException e) {
            return;
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        fail();
    }

    public void testSign_nullPrivateKey() {
        try {
            crypto.generateSignature(TEXT.getBytes(), null);
        } catch (NullArgumentException e) {
            return;
        } catch (SigningException e) {
            e.printStackTrace();
        }
        fail();
    }

    public void testSign() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());

        assertNotNull(signature);
    }

    public void testSign_stream_nullStream() throws SignatureException, CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        try {
            crypto.generateSignature((InputStream) null, keyPair.getPrivateKey());
        } catch (NullArgumentException e) {
            return;
        }
        fail();
    }

    public void testSign_stream_nullPrivateKey() throws SignatureException {
        try {
            crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()), null);
        } catch (NullArgumentException e) {
            return;
        } catch (SigningException e) {
            e.printStackTrace();
        }
        fail();
    }

    public void testSign_stream() throws SignatureException, CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPrivateKey());

        assertNotNull(signature);
    }

    public void testSign_stream_compareToByteArraySign() throws SignatureException, CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        byte[] streamSignature = crypto.generateSignature(new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPrivateKey());

        assertNotNull(signature);
        assertNotNull(streamSignature);
        assertArrayEquals(signature, streamSignature);
    }

    public void testVerify() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verifySignature(TEXT.getBytes(), signature, keyPair.getPublicKey());

        assertTrue(valid);
    }

    public void testVerify_invalidSignature() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verifySignature(TEXT.getBytes(), INVALID_SIGNATURE, keyPair.getPublicKey());

        assertFalse(valid);
    }

    public void testVerify_stream() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verifySignature(signature, new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPublicKey());

        assertTrue(valid);
    }

    public void testVerify_stream_invalidSignature() throws CryptoException {
        com.virgilsecurity.sdk.crypto.VirgilKeyPair keyPair = crypto.generateKeys();
        crypto.generateSignature(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verifySignature(INVALID_SIGNATURE, new ByteArrayInputStream(TEXT.getBytes()),
                keyPair.getPublicKey());

        assertFalse(valid);
    }
}
