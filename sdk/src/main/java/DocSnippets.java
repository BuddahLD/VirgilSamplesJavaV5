/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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
package main.java;

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.exceptions.VirgilKeyIsAlreadyExistsException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.storage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.storage.KeyStorage;
import com.virgilsecurity.sdk.storage.PrivateKeyStorage;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Tuple;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * @author Danylo Oliinyk
 */
public class DocSnippets {

    private CardManager cardManager;
    private CardCrypto cardCrypto;
    private VirgilCrypto virgilCrypto;
    private AccessTokenProvider tokenProvider;

    private void initialize_json_web_token_generator_and_provider() {
        // [API_PRIVATE_KEY_BASE_64] you can find in Virgil dashboard
        String apiKeyBase64 = "[API_PRIVATE_KEY_BASE_64]";
        byte[] privateKeyData = ConvertionUtils.base64ToBytes(apiKeyBase64);

        // Import a private key
        VirgilCrypto crypto = new VirgilCrypto();
        PrivateKey apiKey = null;
        try {
            apiKey = crypto.importPrivateKey(privateKeyData);
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        // Lifetime of json web token, after specified time span it will be expired
        TimeSpan ttl = TimeSpan.fromTime(5, TimeUnit.MINUTES); // 5 minutes to expire

        // [APP_ID] and [API_PUBLIC_KEY] you can find in Virgil dashboard
        JwtGenerator jwtGenerator = new JwtGenerator("[APP_ID]", apiKey, "[API_PUBLIC_KEY]", ttl,
                                                     new VirgilAccessTokenSigner());

        // [IDENTITY] should be equal to the Card's identity that will be published (!!!)
        tokenProvider = new GeneratorJwtProvider(jwtGenerator, "[IDENTITY]");
    }

    private void initialize_virgil_sdk_client() {
        cardCrypto = new VirgilCardCrypto();
        CardVerifier cardVerifier = new VirgilCardVerifier(cardCrypto);
        cardManager = new CardManager.Builder().setAccessTokenProvider(tokenProvider)
                                               .setCrypto(cardCrypto)
                                               .setCardVerifier(cardVerifier)
                                               .build();
    }

    private void data_decryption() throws VirgilException {
        String ciphertext = "Base64 encoded string";

        // load a Virgil Key from device storage
        VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter(virgilCrypto);
        KeyStorage keyStorage = new JsonFileKeyStorage();
        PrivateKeyStorage privateKeyStorage = new PrivateKeyStorage(privateKeyExporter, keyStorage);

        Tuple<PrivateKey, Map<String, String>> privateKeyEntry = privateKeyStorage.load(
                "[KEY_NAME]"); // TODO: 2/22/18 add Password
        PrivateKey bobKey = privateKeyEntry.getLeft();

        // decrypt a ciphertext using loaded Virgil Private Key
        byte[] decryptedMessage = virgilCrypto.decrypt(ConvertionUtils.base64ToBytes(ciphertext),
                                                       (VirgilPrivateKey) bobKey);

        String originalMessage = ConvertionUtils.toString(decryptedMessage);
    }

    private void data_encryption() throws VirgilException, VirgilServiceException {
        // search for Virgil Cards
        List<Card> bobCards = cardManager.searchCards("[IDENTITY_FOR_SEARCH]");

        String message = "Hey Bob, how it's going bro?";

        List<VirgilPublicKey> bobRelevantCardsPublicKeys = new ArrayList<>();
        for (Card card : bobCards) {
            if (!card.isOutdated()) {
                bobRelevantCardsPublicKeys.add((VirgilPublicKey) card.getPublicKey());
            }
        }

        // encrypt the message using found Virgil Cards
        byte[] encodedMessage = virgilCrypto.encrypt(message.getBytes(), bobRelevantCardsPublicKeys);
        String ciphertext = ConvertionUtils.toBase64String(encodedMessage);
    }

    private void decrypt_verify() throws VirgilException, VirgilServiceException {
        String ciphertext = "Base64 encoded string";

        // load a Virgil Key from device storage
        VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter(virgilCrypto);
        KeyStorage keyStorage = new JsonFileKeyStorage();
        PrivateKeyStorage privateKeyStorage = new PrivateKeyStorage(privateKeyExporter, keyStorage);

        Tuple<PrivateKey, Map<String, String>> privateKeyEntry = privateKeyStorage.load(
                "[KEY_NAME]"); // TODO: 2/22/18 add Password
        PrivateKey bobKey = privateKeyEntry.getLeft();

        // get a sender's Virgil Card
        Card aliceCard = cardManager.getCard("[ALICE_CARD_ID]");

        // decrypt the message
        byte[] decryptedMessage = virgilCrypto.decryptThenVerify(ConvertionUtils.base64ToBytes(ciphertext),
                                                                 (VirgilPrivateKey) bobKey,
                                                                 Collections.singletonList(
                                                                         (VirgilPublicKey) aliceCard.getPublicKey()));
        String originalMessage = ConvertionUtils.toString(decryptedMessage);
    }

    private void encrypting_for_multiple() throws VirgilException, VirgilServiceException {
        // search for Cards
        List<Card> bobCards = cardManager.searchCards("[IDENTITY_FOR_SEARCH]");
        // message for encryption
        String message = "Hey Bob, are you crazy?";

        List<VirgilPublicKey> bobRelevantCardsPublicKeys = new ArrayList<>();
        for (Card card : bobCards) {
            if (!card.isOutdated()) {
                bobRelevantCardsPublicKeys.add((VirgilPublicKey) card.getPublicKey());
            }
        }

        // encrypt the message
        byte[] encodedMessage = virgilCrypto.encrypt(message.getBytes(), bobRelevantCardsPublicKeys);
        String ciphertext = ConvertionUtils.toBase64String(encodedMessage);
    }

    private void sign_encrypt() throws VirgilException, VirgilServiceException {
        // load a Virgil Key from device storage
        VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter(virgilCrypto);
        KeyStorage keyStorage = new JsonFileKeyStorage();
        PrivateKeyStorage privateKeyStorage = new PrivateKeyStorage(privateKeyExporter, keyStorage);

        Tuple<PrivateKey, Map<String, String>> privateKeyEntry = privateKeyStorage.load(
                "[KEY_NAME]"); // TODO: 2/22/18 add Password
        PrivateKey aliceKey = privateKeyEntry.getLeft();

        // search for Virgil Cards
        List<Card> bobCards = cardManager.searchCards("[IDENTITY_FOR_SEARCH]");
        List<VirgilPublicKey> bobRelevantCardsPublicKeys = new ArrayList<>();
        for (Card card : bobCards) {
            if (!card.isOutdated()) {
                bobRelevantCardsPublicKeys.add((VirgilPublicKey) card.getPublicKey());
            }
        }

        // prepare the message
        String message = "Hey Bob, are you crazy?";

        // sign and encrypt the message
        byte[] encodedMessage = virgilCrypto.signThenEncrypt(message.getBytes(),
                                                             (VirgilPrivateKey) aliceKey,
                                                             bobRelevantCardsPublicKeys);
        String ciphertext = ConvertionUtils.toBase64String(encodedMessage);
    }

    private void create_signature() throws CryptoException {
        VirgilPrivateKey aliceKey = virgilCrypto.generateKeys().getPrivateKey();

        // prepare a message
        String message = "Hey Bob, hope you are doing well.";

        // generate signature
        byte[] signature = cardCrypto.generateSignature(message.getBytes(), aliceKey);
    }

    private void load_key() throws VirgilException {
        // load Virgil Key
        VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter(virgilCrypto);
        KeyStorage keyStorage = new JsonFileKeyStorage();
        PrivateKeyStorage privateKeyStorage = new PrivateKeyStorage(privateKeyExporter, keyStorage);

        Tuple<PrivateKey, Map<String, String>> privateKeyEntry = privateKeyStorage.load(
                "[KEY_NAME]"); // TODO: 2/22/18 add Password
        PrivateKey aliceKey = privateKeyEntry.getLeft();
    }

    private void verify_signature() throws Exception {
        String message = "Hey Bob, hope you are doing well.";
        String signature = "Base64-encoded string";

        // search for Virgil Card
        Card aliceCard = cardManager.getCard("[ALICE_CARD_ID_HERE]");

        // verify signature using Alice's Virgil Card
        if (!virgilCrypto.verifySignature(signature.getBytes(), message.getBytes(),
                                          (VirgilPublicKey) aliceCard.getPublicKey())) {
            throw new Exception("Aha... Alice it's not you.");
        }
    }

    private void create_key_and_card() throws VirgilKeyIsAlreadyExistsException, CryptoException {
        // generate a new Virgil Key
        VirgilKeyPair aliceKeyPair = virgilCrypto.generateKeys();

        VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter(virgilCrypto);
        KeyStorage keyStorage = new JsonFileKeyStorage();
        PrivateKeyStorage privateKeyStorage = new PrivateKeyStorage(privateKeyExporter, keyStorage);

        // save the Virgil Key into the storage
        privateKeyStorage.store(aliceKeyPair.getPrivateKey(), "[KEY_NAME]", null); // TODO: 2/22/18 add Password

        // create a Virgil Card
        RawSignedModel aliceRawCard = cardManager.generateRawCard(aliceKeyPair.getPrivateKey(),
                                                                  aliceKeyPair.getPublicKey(),
                                                                  "[IDENTITY]");
        Card aliceCard = Card.parse(cardCrypto, aliceRawCard);
    }

    private void export_card() throws CryptoException {
        // generate a new Virgil Key
        VirgilKeyPair aliceKeyPair = virgilCrypto.generateKeys();

        RawSignedModel aliceRawCard = cardManager.generateRawCard(aliceKeyPair.getPrivateKey(),
                                                                  aliceKeyPair.getPublicKey(),
                                                                  "[IDENTITY]");
        Card aliceCard = Card.parse(cardCrypto, aliceRawCard);

        // export a Virgil Card to string
        String exportedAliceCard = cardManager.exportCardAsString(aliceCard);
    }

    private void find_card_by_id() throws CryptoException, VirgilServiceException {
        Card aliceCard = cardManager.getCard("[ALICE_CARD_ID]");
    }

    private void import_card() throws CryptoException {
        // base64 string
        String exportedAliceCard = "";

        // import a Virgil Card from string
        Card aliceCard = cardManager.importCardAsString(exportedAliceCard);
    }

    private void publish_card() throws CryptoException, VirgilServiceException {
        VirgilKeyPair aliceKeyPair = virgilCrypto.generateKeys();

        RawSignedModel aliceRawCard = cardManager.generateRawCard(aliceKeyPair.getPrivateKey(),
                                                                  aliceKeyPair.getPublicKey(),
                                                                  "[IDENTITY]");

        // publish a Virgil Card
        cardManager.publishCard(aliceRawCard);
    }

    private void validating_cards() throws VirgilException, VirgilServiceException {
        // set verifier to Card Manager
        CardCrypto cardCrypto = new VirgilCardCrypto();
        CardVerifier cardVerifier = new VirgilCardVerifier(cardCrypto);
        cardManager = new CardManager.Builder().setAccessTokenProvider(tokenProvider)
                                               .setCrypto(cardCrypto)
                                               .setCardVerifier(cardVerifier)
                                               .build();

        List<Card> aliceCards = cardManager.searchCards("[IDENTITY_FOR_SEARCH]");
    }

    private void export_key() throws CryptoException {
        // generate a new Virgil Private Key
        VirgilPrivateKey aliceKey = virgilCrypto.generateKeys().getPrivateKey();

        // export the Virgil Key
        byte[] exportedAliceKeyData = virgilCrypto.exportPrivateKey(aliceKey, "[OPTIONAL_KEY_PASSWORD]");
        String exportedAliceKey = ConvertionUtils.toBase64String(exportedAliceKeyData);
    }

    private void generating() throws CryptoException {
        // generate a new Virgil Private Key
        VirgilPrivateKey aliceKey = virgilCrypto.generateKeys().getPrivateKey();
    }

    private void import_key() throws CryptoException {
        // initialize a buffer from base64 encoded string
        VirgilPrivateKey aliceKey = virgilCrypto.importPrivateKey(
                ConvertionUtils.base64ToBytes("[BASE64_ENCODED_VIRGIL_KEY]"), "[OPTIONAL_KEY_PASSWORD]");
    }

    private void import_key_with_exporter() throws CryptoException {
        // initialize a buffer from base64 encoded string
        VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter();
        VirgilPrivateKey aliceKey = (VirgilPrivateKey) privateKeyExporter.importPrivateKey(
                ConvertionUtils.base64ToBytes("[BASE64_ENCODED_VIRGIL_KEY]")); // TODO: 2/22/18 add Password
    }

    private void key_specific_generation() throws CryptoException {
        // initialize Crypto with specific key pair type
        VirgilCrypto crypto = new VirgilCrypto(KeysType.EC_BP512R1);

        // generate a new Virgil Key
        VirgilPrivateKey aliceKey = virgilCrypto.generateKeys().getPrivateKey();
    }

    private void virgil_key_load_key() throws VirgilException {
        // load a Virgil Key from storage
        VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter(virgilCrypto);
        KeyStorage keyStorage = new JsonFileKeyStorage();
        PrivateKeyStorage privateKeyStorage = new PrivateKeyStorage(privateKeyExporter, keyStorage);

        Tuple<PrivateKey, Map<String, String>> privateKeyEntry = privateKeyStorage.load(
                "[KEY_NAME]"); // TODO: 2/22/18 add Password
        PrivateKey aliceKey = privateKeyEntry.getLeft();
    }

    private void save_key() throws CryptoException {
        VirgilKeyPair aliceKeyPair = virgilCrypto.generateKeys();

        VirgilPrivateKeyExporter privateKeyExporter = new VirgilPrivateKeyExporter(virgilCrypto);
        KeyStorage keyStorage = new JsonFileKeyStorage();
        PrivateKeyStorage privateKeyStorage = new PrivateKeyStorage(privateKeyExporter, keyStorage);

        // save the Virgil Key into the storage
        privateKeyStorage.store(aliceKeyPair.getPrivateKey(), "[KEY_NAME]", null); // TODO: 2/22/18 add Password
    }
}
