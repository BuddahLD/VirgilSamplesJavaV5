
/*
 * Copyright (c) 2017, Virgil Security, Inc.
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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilKeyIsAlreadyExistsException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.IdentityType;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.highlevel.AppCredentials;
import com.virgilsecurity.sdk.highlevel.CardVerifierInfo;
import com.virgilsecurity.sdk.highlevel.EmailConfirmation;
import com.virgilsecurity.sdk.highlevel.IdentityValidationToken;
import com.virgilsecurity.sdk.highlevel.IdentityVerificationAttempt;
import com.virgilsecurity.sdk.highlevel.StringEncoding;
import com.virgilsecurity.sdk.highlevel.VirgilApi;
import com.virgilsecurity.sdk.highlevel.VirgilApiContext;
import com.virgilsecurity.sdk.highlevel.VirgilApiImpl;
import com.virgilsecurity.sdk.highlevel.VirgilBuffer;
import com.virgilsecurity.sdk.highlevel.VirgilCard;
import com.virgilsecurity.sdk.highlevel.VirgilCards;
import com.virgilsecurity.sdk.highlevel.VirgilKey;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.storage.JsonFileKeyStorage;
import com.virgilsecurity.sdk.storage.KeyStorage;
import com.virgilsecurity.sdk.storage.PrivateKeyStorage;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.Tuple;

/**
 * @author Danylo Oliinyk
 */
public class DocSnippets {

    CardManager cardManager;
    CardCrypto cardCrypto;
    VirgilCrypto virgilCrypto;
    AccessTokenProvider tokenProvider;
    JwtGenerator jwtGenerator;

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
        jwtGenerator = new JwtGenerator("[APP_ID]", apiKey, "[API_PUBLIC_KEY]", ttl, new VirgilAccessTokenSigner());

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

    private void encrypting_for_multiple() throws VirgilException {
        // search for Cards
        VirgilCards bobCards = virgil.getCards().find("bob");
        // message for encryption
        String message = "Hey Bob, are you crazy?";
        // encrypt the message
        String ciphertext = bobCards.encrypt(message).toString(StringEncoding.Base64);
    }

    private void sign_encrypt() throws VirgilException {
        // load a Virgil Key from device storage
        VirgilKey aliceKey = virgil.getKeys().load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]");

        // search for Virgil Cards
        VirgilCards bobCards = virgil.getCards().find("bob");

        // prepare the message
        String message = "Hey Bob, are you crazy?";

        // sign and encrypt the message
        String ciphertext = aliceKey.signThenEncrypt(message, bobCards).toString(StringEncoding.Base64);
    }

    private void create_signature() {
        VirgilKey aliceKey = virgil.getKeys().generate();

        /** Snippet starts here */

        // prepare a message
        String message = "Hey Bob, hope you are doing well.";

        // generate signature
        VirgilBuffer signature = aliceKey.sign(message);
    }

    private void load_key() throws VirgilException {
        // load Virgil Key
        VirgilKey aliceKey = virgil.getKeys().load("[KEY_NAME]", "[KEY _PASSWORD]");
    }

    private void verify_signature() throws Exception {
        String message = "Hey Bob, hope you are doing well.";
        String signature = "Base64-encoded string";

        /** Snippet starts here */

        // search for Virgil Card
        VirgilCard aliceCard = virgil.getCards().get("[ALICE_CARD_ID_HERE]");

        // verify signature using Alice's Virgil Card
        if (!aliceCard.verify(message, signature)) {
            throw new Exception("Aha... Alice it's not you.");
        }
    }

    private void create_key_and_card() throws VirgilKeyIsAlreadyExistsException {
        /** Snippet starts here */

        // generate a new Virgil Key
        VirgilKey aliceKey = virgil.getKeys().generate();

        // save the Virgil Key into the storage
        aliceKey.save("[KEY_NAME]", "[KEY_PASSWORD]");

        // create a Virgil Card
        VirgilCard aliceCard = virgil.getCards().create("alice", aliceKey);
    }

    private void create_key_and_global_card() throws VirgilKeyIsAlreadyExistsException {
        /** Snippet starts here */

        // generate a Virgil Key
        VirgilKey aliceKey = virgil.getKeys().generate();

        // save the Virgil Key into storage
        aliceKey.save("[KEY_NAME]", "[KEY_PASSWORD]");

        // create a global Virgil Card
        VirgilCard aliceCard = virgil.getCards().createGlobal("alice@virgilsecurity.com", aliceKey, IdentityType.EMAIL);
    }

    private void export_card() {
        VirgilKey aliceKey = virgil.getKeys().generate();
        VirgilCard aliceCard = virgil.getCards().create("alice", aliceKey);

        /** Snippet starts here */

        // export a Virgil Card to string
        String exportedAliceCard = aliceCard.export();
    }

    private void find_card_by_criteria() throws VirgilException {
        /** Snippet starts here */

        // search for all User's Virgil Cards.
        VirgilCards aliceCards = virgil.getCards().find("alice");

        // search for all User's Virgil Cards with identity type 'member'
        VirgilCards bobCards = virgil.getCards().find("member", Arrays.asList("bob"));
    }

    private void find_card_by_id() {
        /** Snippet starts here */

        VirgilCard aliceCard = virgil.getCards().get("[ALICE_CARD_ID]");
    }

    private void find_global_card_by_criteria() throws VirgilException {
        /** Snippet starts here */

        // search for all Global Virgil Cards
        VirgilCards bobGlobalCards = virgil.getCards().findGlobal("bob@virgilsecurity.com");

        // search for Application Virgil Card
        VirgilCards appCards = virgil.getCards().findGlobal("com.username.appname");
    }

    private void import_card() {
        String exportedAliceCard = "";

        /** Snippet starts here */

        // import a Virgil Card from string
        VirgilCard aliceCard = virgil.getCards().importCard(exportedAliceCard);
    }

    private void publish_card() throws CryptoException {
        VirgilKey aliceKey = virgil.getKeys().generate();
        VirgilCard aliceCard = virgil.getCards().create("alice", aliceKey);

        /** Snippet starts here */

        // publish a Virgil Card
        virgil.getCards().publish(aliceCard);
    }

    private void revoke_card() throws CryptoException {
        /** Snippet starts here */

        // get a Virgil Card by ID
        VirgilCard aliceCard = virgil.getCards().get("[USER_CARD_ID_HERE]");

        // revoke a Virgil Card
        virgil.getCards().revoke(aliceCard);
    }

    private void revoke_global_card() throws VirgilException {
        /** Snippet starts here */

        // load a Virgil Key from storage
        VirgilKey aliceKey = virgil.getKeys().load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]");

        // load a Virgil Card from Virgil Services
        VirgilCard aliceCard = virgil.getCards().get("[USER_CARD_ID_HERE]");

        // initiate an identity verification process.
        IdentityVerificationAttempt attempt = aliceCard.checkIdentity();

        // grab a validation token
        IdentityValidationToken token = attempt.confirm(new EmailConfirmation("[CONFIRMATION_CODE]"));

        // revoke a global Virgil Card
        virgil.getCards().revokeGlobal(aliceCard, aliceKey, token);
    }

    private void validating_cards() throws VirgilException {
        /** Snippet starts here */

        VirgilBuffer appPublicKey = VirgilBuffer.from("[YOUR_APP_PUBLIC_KEY_HERE]", StringEncoding.Base64);

        // initialize High Level Api with custom verifiers
        VirgilApiContext context = new VirgilApiContext("[YOUR_ACCESS_TOKEN_HERE]");
        context.setCardVerifiers(Arrays.asList(new CardVerifierInfo("[YOUR_APP_CARD_ID_HERE]", appPublicKey)));

        VirgilApi virgil = new VirgilApiImpl(context);

        VirgilCards aliceCards = virgil.getCards().find("alice");
    }

    private void verify_and_publish_global_card() throws VirgilException {
        VirgilKey aliceKey = virgil.getKeys().generate();
        VirgilCard aliceCard = virgil.getCards().create("alice", aliceKey);

        /** Snippet starts here */

        // initiate identity verification process
        IdentityVerificationAttempt attempt = aliceCard.checkIdentity();

        // confirm an identity and grab the validation token
        IdentityValidationToken token = attempt.confirm(new EmailConfirmation("[CONFIRMATION_CODE]"));

        // publish the Virgil Card
        virgil.getCards().publishGlobal(aliceCard, token);
    }

    private void export_key() {
        /** Snippet starts here */

        // generate a new Virgil Key
        VirgilKey aliceKey = virgil.getKeys().generate();

        // export the Virgil Key
        String exportedAliceKey = aliceKey.export("[OPTIONAL_KEY_PASSWORD]").toString(StringEncoding.Base64);
    }

    private void generating() {
        /** Snippet starts here */

        // generate a new Virgil Key
        VirgilKey aliceKey = virgil.getKeys().generate();
    }

    private void import_key() throws CryptoException {
        /** Snippet starts here */

        // initialize a buffer from base64 encoded string
        VirgilBuffer aliceKeyBuffer = VirgilBuffer.from("[BASE64_ENCODED_VIRGIL_KEY]", StringEncoding.Base64);

        // import Virgil Key from buffer
        VirgilKey aliceKey = virgil.getKeys().importKey(aliceKeyBuffer, "[OPTIONAL_KEY_PASSWORD]");
    }

    private void key_specific_generation() {
        /** Snippet starts here */

        // initialize Crypto with specific key pair type
        Crypto crypto = new VirgilCrypto(KeysType.EC_BP512R1);

        VirgilApiContext context = new VirgilApiContext();
        context.setCrypto(crypto);

        // initialize Virgil SDK using
        VirgilApi virgil = new VirgilApiImpl(context);

        // generate a new Virgil Key
        VirgilKey aliceKey = virgil.getKeys().generate();
    }

    private void virgil_key__load_key() throws VirgilException {
        /** Snippet starts here */

        // load a Virgil Key from storage
        VirgilKey aliceKey = virgil.getKeys().load("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]");
    }

    private void save_key() throws VirgilKeyIsAlreadyExistsException {
        VirgilKey aliceKey = virgil.getKeys().generate();
        /** Snippet starts here */

        // save Virgil Key into storage
        aliceKey.save("[KEY_NAME]", "[OPTIONAL_KEY_PASSWORD]");
    }

    // private void create_key_and_card() {
    // /** Snippet starts here */
    // }
}
