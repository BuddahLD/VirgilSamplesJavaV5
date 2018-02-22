package com.virgilsecurity.virgilsamples;

import android.test.AndroidTestCase;

import com.virgilsecurity.crypto.VirgilHash;
import com.virgilsecurity.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.Fingerprint;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.KeysType;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;

/**
 * Created by Andrii Iakovenko on 07.10.16.
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

    private Crypto crypto;

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

    public void testCalculateFingerprint_null() {
        try {
            crypto.calculateFingerprint(null);
        } catch (NullArgumentException e) {
            return;
        }
        fail();
    }

    public void testCalculateFingerprint() {
        Fingerprint fingerprint = crypto.calculateFingerprint(TEXT.getBytes());
        assertNotNull(fingerprint);
        assertNotNull(fingerprint.getValue());
        assertTrue(fingerprint.getValue().length > 0);
    }

    public void testComputeHash_nullData() {
        try {
            crypto.computeHash(null, HashAlgorithm.MD5);
        } catch (NullArgumentException e) {
            return;
        }
        fail();
    }

    public void testComputeHash() {
        try {
            for (HashAlgorithm algorithm : HashAlgorithm.values()) {
                byte[] hash = crypto.computeHash(null, algorithm);

                assertNotNull(hash);
                assertTrue(hash.length > 0);
            }
        } catch (NullArgumentException e) {
            return;
        }
        fail();
    }

    public void testDecrypt() {
        List<PrivateKey> privateKeys = new ArrayList<>();
        List<PublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < MAX_RECIPIENTS; i++) {
            KeyPair keyPair = crypto.generateKeys();
            privateKeys.add(keyPair.getPrivateKey());
            recipients.add(keyPair.getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients.toArray(new PublicKey[0]));
        for (PrivateKey privateKey : privateKeys) {
            byte[] decrypted = crypto.decrypt(encrypted, privateKey);
            assertArrayEquals(TEXT.getBytes(), decrypted);
        }
    }

    public void testDecrypt_stream() throws IOException, DecryptionException {
        List<PrivateKey> privateKeys = new ArrayList<>();
        List<PublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < MAX_RECIPIENTS; i++) {
            KeyPair keyPair = crypto.generateKeys();
            privateKeys.add(keyPair.getPrivateKey());
            recipients.add(keyPair.getPublicKey());
        }
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients.toArray(new PublicKey[0]));
        for (PrivateKey privateKey : privateKeys) {
            try (InputStream is = new ByteArrayInputStream(encrypted);
                     ByteArrayOutputStream os = new ByteArrayOutputStream()) {
                crypto.decrypt(is, os, privateKey);

                byte[] decrypted = os.toByteArray();

                assertArrayEquals(TEXT.getBytes(), decrypted);
            }
        }
    }

    public void testEncrypt() {
        List<PublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < MAX_RECIPIENTS; i++) {
            recipients.add(crypto.generateKeys().getPublicKey());
        }
        crypto.encrypt(TEXT.getBytes(StandardCharsets.UTF_8), crypto.generateKeys().getPublicKey());
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), recipients.toArray(new PublicKey[0]));

        assertNotNull(encrypted);
    }

    public void testEncrypt_noRecipients_success() {
        byte[] encrypted = crypto.encrypt(TEXT.getBytes(), new PublicKey[0]);

        assertNotNull(encrypted);
    }

    public void testEncrypt_stream() throws IOException, EncryptionException {
        List<PublicKey> recipients = new ArrayList<>();
        for (int i = 0; i < MAX_RECIPIENTS; i++) {
            recipients.add(crypto.generateKeys().getPublicKey());
        }
        try (OutputStream os = new ByteArrayOutputStream()) {
            crypto.encrypt(new ByteArrayInputStream(TEXT.getBytes()), os, recipients.toArray(new PublicKey[0]));
        }
    }

    public void testExportPrivateKey() {
        KeyPair keyPair = crypto.generateKeys();
        byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey());

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    public void testExportPrivateKey_withPassword() {
        KeyPair keyPair = crypto.generateKeys();
        byte[] key = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    public void testExportPublicKey() {
        KeyPair keyPair = crypto.generateKeys();

        byte[] key = crypto.exportPublicKey(keyPair.getPublicKey());

        assertNotNull(key);
        assertTrue(key.length > 0);
    }

    public void testExtractPublicKey() {
        KeyPair keyPair = crypto.generateKeys();

        PublicKey publicKey = crypto.extractPublicKey(keyPair.getPrivateKey());
        assertNotNull(publicKey);
        assertArrayEquals(keyPair.getPublicKey().getId(), publicKey.getId());
        assertArrayEquals(keyPair.getPublicKey().getValue(), publicKey.getValue());
    }

    public void testGenerateKeys() {
        KeyPair keyPair = crypto.generateKeys();

        assertNotNull(keyPair);

        PublicKey publicKey = keyPair.getPublicKey();
        assertNotNull(publicKey);
        assertNotNull(publicKey.getId());
        assertNotNull(publicKey.getValue());

        PrivateKey privateKey = keyPair.getPrivateKey();
        assertNotNull(privateKey);
        assertNotNull(privateKey.getId());
        assertNotNull(privateKey.getValue());
    }

    public void testImportPrivateKey() throws CryptoException {
        KeyPair keyPair = crypto.generateKeys();

        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey());

        PrivateKey importedKey = crypto.importPrivateKey(keyData);

        assertNotNull(importedKey);
        assertNotNull(importedKey.getId());
        assertNotNull(importedKey.getValue());
        assertArrayEquals(keyPair.getPrivateKey().getId(), importedKey.getId());
        assertArrayEquals(keyPair.getPrivateKey().getValue(), importedKey.getValue());
    }

    public void testImportPrivateKey_withPassword() throws CryptoException {
        KeyPair keyPair = crypto.generateKeys();
        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        PrivateKey importedKey = crypto.importPrivateKey(keyData, PASSWORD);

        assertNotNull(importedKey);
        assertNotNull(importedKey.getId());
        assertNotNull(importedKey.getValue());
        assertArrayEquals(keyPair.getPrivateKey().getId(), importedKey.getId());
        assertArrayEquals(keyPair.getPrivateKey().getValue(), importedKey.getValue());
    }

    public void testImportPrivateKey_withWrongPassword() throws CryptoException {
        KeyPair keyPair = crypto.generateKeys();
        byte[] keyData = crypto.exportPrivateKey(keyPair.getPrivateKey(), PASSWORD);

        try {
            crypto.importPrivateKey(keyData, PASSWORD + "1");
        } catch (CryptoException e) {
            return;
        }
        fail();
    }

    public void testImportPublicKey() {
        KeyPair keyPair = crypto.generateKeys();

        byte[] keyData = crypto.exportPublicKey(keyPair.getPublicKey());
        PublicKey publicKey = crypto.importPublicKey(keyData);

        assertNotNull(publicKey);
        assertNotNull(publicKey.getId());
        assertNotNull(publicKey.getValue());
        assertArrayEquals(keyPair.getPublicKey().getId(), publicKey.getId());
        assertArrayEquals(keyPair.getPublicKey().getValue(), publicKey.getValue());
    }

    public void testSign_nullData() {
        try {
            KeyPair keyPair = crypto.generateKeys();
            crypto.sign((byte[]) null, keyPair.getPrivateKey());
        } catch (NullArgumentException e) {
            return;
        }
        fail();
    }

    public void testSign_nullPrivateKey() {
        try {
            crypto.sign(TEXT.getBytes(), null);
        } catch (NullArgumentException e) {
            return;
        }
        fail();
    }

    public void testSign() {
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());

        assertNotNull(signature);
    }

    public void testSign_stream_nullStream() throws SignatureException {
        KeyPair keyPair = crypto.generateKeys();
        try {
            crypto.sign((InputStream) null, keyPair.getPrivateKey());
        } catch (NullArgumentException e) {
            return;
        }
        fail();
    }

    public void testSign_stream_nullPrivateKey() throws SignatureException {
        try {
            crypto.sign(new ByteArrayInputStream(TEXT.getBytes()), null);
        } catch (NullArgumentException e) {
            return;
        }
        fail();
    }

    public void testSign_stream() throws SignatureException {
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPrivateKey());

        assertNotNull(signature);
    }

    public void testSign_stream_compareToByteArraySign() throws SignatureException {
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        byte[] streamSignature = crypto.sign(new ByteArrayInputStream(TEXT.getBytes()), keyPair.getPrivateKey());

        assertNotNull(signature);
        assertNotNull(streamSignature);
        assertArrayEquals(signature, streamSignature);
    }

    public void testVerify() {
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verify(TEXT.getBytes(), signature, keyPair.getPublicKey());

        assertTrue(valid);
    }

    public void testVerify_invalidSignature() {
        KeyPair keyPair = crypto.generateKeys();
        crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verify(TEXT.getBytes(), INVALID_SIGNATURE, keyPair.getPublicKey());

        assertFalse(valid);
    }

    public void testVerify_stream() throws VerificationException {
        KeyPair keyPair = crypto.generateKeys();
        byte[] signature = crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verify(new ByteArrayInputStream(TEXT.getBytes()), signature, keyPair.getPublicKey());

        assertTrue(valid);
    }

    public void testVerify_stream_invalidSignature() throws VerificationException {
        KeyPair keyPair = crypto.generateKeys();
        crypto.sign(TEXT.getBytes(), keyPair.getPrivateKey());
        boolean valid = crypto.verify(new ByteArrayInputStream(TEXT.getBytes()), INVALID_SIGNATURE,
                keyPair.getPublicKey());

        assertFalse(valid);
    }
}
