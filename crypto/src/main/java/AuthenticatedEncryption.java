
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import com.virgilsecurity.crypto.VirgilBase64;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;

/**
 * Authenticated encryption sample.
 * 
 * @author Danylo Oliinyk
 *
 */
public class AuthenticatedEncryption {

    public static void main(String[] args) throws IOException, VirgilException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Enter the text to be signed with alice's Private key: ");
        String dataToSign = br.readLine();
        byte[] data = dataToSign.getBytes();
        System.out.println();

        // Initialize Crypto
        Crypto crypto = new VirgilCrypto();

        // Generate keys for Alice and Bob
        KeyPair alice = crypto.generateKeys();
        KeyPair bob = crypto.generateKeys();

        // Sign then Encrypt
        byte[] cipherData = crypto.signThenEncrypt(data, alice.getPrivateKey(), bob.getPublicKey());

        System.out.println(String.format("Cipher text in Base64:\n %1$s", VirgilBase64.encode(cipherData)));

        // Decrypt then Verify
        byte[] decryptedData = crypto.decryptThenVerify(cipherData, bob.getPrivateKey(), alice.getPublicKey());

        System.out.println(String.format("Decrypted text:\n %1$s", new String(decryptedData, StandardCharsets.UTF_8)));
    }
}
