package com.virgilsecurity.virgilsamples;

import android.test.AndroidTestCase;
import android.util.Log;

import com.virgilsecurity.sdk.device.DefaultDeviceManager;
import com.virgilsecurity.sdk.device.DeviceManager;

/**
 * Created by Andrii Iakovenko.
 */
public class DeviceManagerTest extends AndroidTestCase {


    private static final String TAG = "DeviceManager";

    private DeviceManager deviceManager;

    @Override
    protected void setUp() throws Exception {
        deviceManager = new DefaultDeviceManager();
    }

    public void testDeviceName() {
        String deviceName = deviceManager.getDeviceName();

        assertNotNull(deviceName);
        Log.d(TAG, deviceName);
    }

    public void testSystemName() {
        String systemName = deviceManager.getSystemName();

        assertNotNull(systemName);
        Log.d(TAG, systemName);
    }

    public void testSystemVersion() {
        String systemVersion = deviceManager.getSystemVersion();

        assertNotNull(systemVersion);
        Log.d(TAG, systemVersion);
    }

    public void testDeviceModel() {
        String deviceModel = deviceManager.getDeviceModel();

        assertNotNull(deviceModel);
        Log.d(TAG, deviceModel);
    }
}
