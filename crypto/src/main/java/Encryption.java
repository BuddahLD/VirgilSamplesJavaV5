package main.java;
/*
 * Copyright (c) 2016, Virgil Security, Inc.
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of virgil nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import com.virgilsecurity.crypto.VirgilBase64;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

import java.nio.charset.StandardCharsets;

/**
 * @author Danylo Oliinyk
 *
 */
public class Encryption {

    public static void main(String[] args) throws VirgilException {
        String text = "Encrypt me, Please!!!";

        // Initialize Crypto
        VirgilCrypto crypto = new VirgilCrypto();

        // Generate generate public/private key pair for key recipient
        VirgilKeyPair keyPair = crypto.generateKeys();

        PublicKey publicKey = keyPair.getPublicKey();
        PrivateKey privateKey = keyPair.getPrivateKey();

        // Encrypting data for multiple recipients key/password
        byte[] encryptedData = crypto.encrypt(text.getBytes(), (VirgilPublicKey) publicKey);

        System.out.println(String.format("Cipher text in Base64:\n %1$s", VirgilBase64.encode(encryptedData)));

        // Decrypt data with private key
        byte[] decryptedData = crypto.decrypt(encryptedData, (VirgilPrivateKey) privateKey);

        System.out.println(String.format("Decrypted text:\n %1$s", new String(decryptedData, StandardCharsets.UTF_8)));
    }
}
