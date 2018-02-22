package com.virgilsecurity.virgilsamples;

import android.test.AndroidTestCase;
import android.util.Log;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.device.DeviceManager;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.KeyStorage;
import com.virgilsecurity.sdk.storage.VirgilKeyEntry;
import com.virgilsecurity.sdk.storage.VirgilKeyStorage;

import java.util.Date;

import static org.junit.Assert.assertArrayEquals;

/**
 * Created by Andrii Iakovenko.
 */
public class KeyStorageTest extends AndroidTestCase {


    private static final String TAG = "KeyStorage";

    private KeyStorage keyStorage;
    private Crypto crypto;

    @Override
    protected void setUp() throws Exception {
        keyStorage = new VirgilKeyStorage(getContext().getFilesDir().getAbsolutePath());
        crypto = new VirgilCrypto();
    }

    public void testAll() {
        String keyName = "key" + new Date().getTime();
        KeyPair keyPair = crypto.generateKeys();
        byte[] exportedPrivateKey = crypto.exportPrivateKey(keyPair.getPrivateKey());

        assertFalse(keyStorage.exists(keyName));

        KeyEntry entry = new VirgilKeyEntry(keyName, exportedPrivateKey);
        keyStorage.store(entry);

        assertTrue(keyStorage.exists(keyName));

        KeyEntry loadedEntry = keyStorage.load(keyName);
        assertNotNull(loadedEntry);
        assertEquals(entry.getName(), loadedEntry.getName());
        assertArrayEquals(entry.getValue(), loadedEntry.getValue());

        keyStorage.delete(keyName);

        assertFalse(keyStorage.exists(keyName));

    }
}
