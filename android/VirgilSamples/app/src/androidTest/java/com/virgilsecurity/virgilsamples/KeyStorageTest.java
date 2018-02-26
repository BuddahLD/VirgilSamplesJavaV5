package com.virgilsecurity.virgilsamples;

import android.test.AndroidTestCase;

import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.storage.DefaultKeyStorage;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.KeyStorage;

import java.io.File;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertArrayEquals;

/**
 * Created by Danylo Oliinyk.
 */
public class KeyStorageTest extends AndroidTestCase {


    private static final String TAG = "KeyStorage";

    private KeyStorage keyStorage;
    private VirgilCrypto crypto;
    private File tmpDir;

    @Override
    protected void setUp() throws Exception {
        tmpDir = new File(System.getProperty("java.io.tmpdir") + File.separator + UUID.randomUUID().toString());
        keyStorage = new DefaultKeyStorage(tmpDir.getAbsolutePath(), UUID.randomUUID().toString());
        crypto = new VirgilCrypto();
    }

    public void testAll() throws CryptoException {
        String keyName = "key" + new Date().getTime();
        VirgilKeyPair keyPair = crypto.generateKeys();
        byte[] exportedPrivateKey = crypto.exportPrivateKey(keyPair.getPrivateKey(), null);

        assertFalse(keyStorage.exists(keyName));

        KeyEntry entry = new TestKeyEntry(keyName, exportedPrivateKey);
        keyStorage.store(entry);

        assertTrue(keyStorage.exists(keyName));

        KeyEntry loadedEntry = keyStorage.load(keyName);
        assertNotNull(loadedEntry);
        assertEquals(entry.getName(), loadedEntry.getName());
        assertArrayEquals(entry.getValue(), loadedEntry.getValue());

        keyStorage.delete(keyName);

        assertFalse(keyStorage.exists(keyName));

    }

    private class TestKeyEntry implements KeyEntry {
        private String keyName;
        private byte[] keyValue;
        private Map<String, String> keyMeta;

        public TestKeyEntry() {
            keyMeta = new HashMap<>();
        }

        public TestKeyEntry(String name, byte[] value) {
            this();
            this.keyName = name;
            this.keyValue = value;
        }

        /*
         * (non-Javadoc)
         *
         * @see com.virgilsecurity.sdk.crypto.KeyEntry#getName()
         */
        @Override
        public String getName() {
            return keyName;
        }

        /*
         * (non-Javadoc)
         *
         * @see com.virgilsecurity.sdk.crypto.KeyEntry#setName(java.lang.String)
         */
        @Override
        public void setName(String name) {
            this.keyName = name;
        }

        /*
         * (non-Javadoc)
         *
         * @see com.virgilsecurity.sdk.storage.KeyEntry#getValue()
         */
        @Override
        public byte[] getValue() {
            return keyValue;
        }

        /*
         * (non-Javadoc)
         *
         * @see com.virgilsecurity.sdk.storage.KeyEntry#setValue(byte[])
         */
        @Override
        public void setValue(byte[] value) {
            this.keyValue = value;
        }

        /*
         * (non-Javadoc)
         *
         * @see com.virgilsecurity.sdk.crypto.KeyEntry#getMeta()
         */
        @Override
        public Map<String, String> getMeta() {
            return this.keyMeta;
        }

        /*
         * (non-Javadoc)
         *
         * @see com.virgilsecurity.sdk.storage.KeyEntry#setMeta(java.util.Map)
         */
        @Override
        public void setMeta(Map<String, String> meta) {
            this.keyMeta = meta;
        }
    }
}
