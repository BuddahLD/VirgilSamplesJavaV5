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
import com.virgilsecurity.sdk.cards.ModelSigner;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.exceptions.VirgilCardVerificationException;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.jwt.accessProviders.GeneratorJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * This sample will help you get started using the Crypto Library and Virgil Keys Services for the most popular
 * platforms and languages.
 *
 * @author Danylo Oliinyk
 */
public class Quickstart {

    public static void main(String[] args) throws Exception {

        String appID = "[YOUR_APP_ID_HERE]";
        String apiKeyBase64 = "[API_PRIVATE_KEY_BASE_64]";
        byte[] privateKeyData = ConvertionUtils.base64ToBytes(apiKeyBase64);

        // Initializing Virgil Crypto
        VirgilCrypto crypto = new VirgilCrypto();
        // Initializing Card Crypto
        CardCrypto cardCrypto = new VirgilCardCrypto();
        // Initializing Card Verifier
        CardVerifier cardVerifier = new VirgilCardVerifier(cardCrypto);

        PrivateKey apiKey = null;
        try {
            apiKey = crypto.importPrivateKey(privateKeyData);
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        // Lifetime of json web token, after specified time span it will be expired
        TimeSpan ttl = TimeSpan.fromTime(5, TimeUnit.MINUTES); // 5 minutes to expire

        // Initializing Jwt generator
        // [APP_ID] and [API_PUBLIC_KEY] you can find in Virgil dashboard
        JwtGenerator jwtGenerator = new JwtGenerator("[APP_ID]", apiKey, "[API_PUBLIC_KEY]", ttl,
                                                     new VirgilAccessTokenSigner());

        // [IDENTITY] should be equal to the Card's identity that will be published (!!!)
        AccessTokenProvider tokenProvider = new GeneratorJwtProvider(jwtGenerator, "[IDENTITY]");

        // Initializing an API Client
        CardManager cardManager = new CardManager.Builder()
                .setCrypto(cardCrypto)
                .setAccessTokenProvider(tokenProvider)
                .setCardVerifier(cardVerifier)
                .build();

        // Creating a Virgil Card

        // Generate a new Public/Private keypair using VirgilCrypto class.
        VirgilKeyPair keyPair = crypto.generateKeys();

        // Prepare raw card to publish
        RawSignedModel cardModel = cardManager.generateRawCard(keyPair.getPrivateKey(),
                                                                  keyPair.getPublicKey(),
                                                                  "[IDENTITY]");

        // then, use ModelSigner class to sign request with owner signature.
        ModelSigner modelSigner = new ModelSigner(cardCrypto);
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());

        // then, use ModelSigner class to sign request with API signature.
        modelSigner.sign(cardModel, appID, apiKey);

        // Publish a Virgil Card
        Card aliceCard = cardManager.publishCard(cardModel);

        // Get Virgil Card
        Card receivedCard = cardManager.getCard(aliceCard.getIdentifier());

        // Search for Virgil Cards
        List<Card> cards = cardManager.searchCards("[IDENTITY]");

        // If need - you can catch validation exception.
        List<Card> cardsForValidation;
        try {
            cardsForValidation = cardManager.searchCards("");
        } catch (VirgilCardVerificationException e) {
            // Handle validation exception here
        }

        // Outdating a Virgil Card
        // You have to publish card with previousCardId of Card that you want to be outdated
        String previousCardId = aliceCard.getIdentifier();

        // Prepare raw card to publish with previousCardId which is to be outdated
        RawSignedModel cardModelNew = cardManager.generateRawCard(keyPair.getPrivateKey(),
                                                               keyPair.getPublicKey(),
                                                               "[IDENTITY]",
                                                                  previousCardId);

        // then, use ModelSigner class to sign request with owner signature.
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());

        // then, use ModelSigner class to sign request with API signature.
        modelSigner.sign(cardModel, appID, apiKey);

        // Publish a Virgil Card and make outdated the old one
        Card aliceCardNew = cardManager.publishCard(cardModel);
    }
}
