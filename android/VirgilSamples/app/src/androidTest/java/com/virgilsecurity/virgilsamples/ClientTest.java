package com.virgilsecurity.virgilsamples;

import android.test.AndroidTestCase;

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.ModelSigner;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
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
 * Created by Danylo Oliinyk on 07.10.16 at Virgil Security.
 * -__o
 */

public class ClientTest extends AndroidTestCase {

    private static final String SERVICE_SIGN = "SERVICE_SIGN";

    private static String cardId;

    private VirgilKeyPair keyPair;

    public void testFlow() {
//        String appId = "[YOUR_APP_ID_HERE]";
        String appId = "54e071c5c1894aa889e31d6c7864fed5";
//        String apiPublicKey = "[API_PUBLIC_KEY]";
        String apiPublicKey = "MCowBQYDK2VwAyEAeAkxVayBD3F4kGQoa1Mtlgqip5jxBXmPG5JP8PXopQI=";
//        String apiPublicKeyIdentifier = "[API_PUBLIC_KEY_IDENTIFIER]]";
        String apiPublicKeyIdentifier = "981b4b27dbb5720f";
//        String apiKeyBase64 = "[API_PRIVATE_KEY_BASE_64]";
        String apiKeyBase64 = "MC4CAQAwBQYDK2VwBCIEIPupM43Dt7gJwayKl6EO4qFJbvyALQxap1LcgqoYVREb";
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
        JwtGenerator jwtGenerator = new JwtGenerator(appId, apiKey, apiPublicKeyIdentifier, ttl, new VirgilAccessTokenSigner());

        // [IDENTITY] should be equal to the Card's identity that will be published (!!!)
        AccessTokenProvider tokenProvider = new GeneratorJwtProvider(jwtGenerator, "[IDENTITY]");

        // Initializing Model signer
        ModelSigner modelSigner = new ModelSigner(cardCrypto);

        // Initializing Card Manager
        CardManager cardManager = new CardManager.Builder()
                .setCrypto(cardCrypto)
                .setAccessTokenProvider(tokenProvider)
                .setCardVerifier(cardVerifier)
                .setModelSigner(modelSigner)
                .setCardClient(new CardClient())
                .build();

        // Creating a Virgil Card

        try {
            // Generate a new Public/Private keypair using VirgilCrypto class.
            keyPair = crypto.generateKeys();
        } catch (CryptoException e) {
            // Handle keys generation exception here
        }

        // Prepare raw card to publish
        RawSignedModel cardModel = null;
        try {
            cardModel = cardManager.generateRawCard(keyPair.getPrivateKey(),
                                                    keyPair.getPublicKey(),
                                                    "[IDENTITY]");
        } catch (CryptoException e) {
            // Handle raw card generation exception here
        }

        Card publishedCard = null;
        try {
            modelSigner.sign(cardModel, SERVICE_SIGN, apiKey);

            publishedCard = cardManager.publishCard(cardModel);

            assertNotNull(publishedCard);
            assertNotNull(publishedCard.getIdentifier());
            assertNotNull(publishedCard.getContentSnapshot());
            RawCardContent cardContent =
                    RawCardContent.fromString(ConvertionUtils.toBase64String(publishedCard.getContentSnapshot()));
            assertNotNull(cardContent.getIdentity());
            assertNotNull(cardContent.getCreatedAtTimestamp());
            assertNotNull(cardContent.getIdentity());
            assertNotNull(cardContent.getPublicKey());
            assertNotNull(cardContent.getVersion());

            cardId = publishedCard.getIdentifier();
        } catch (CryptoException | VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Get card
        try {
            Card card = cardManager.getCard(cardId);

            assertNotNull(card);
            assertNotNull(card.getIdentifier());
            assertNotNull(card.getContentSnapshot());
            RawCardContent cardContent =
                    RawCardContent.fromString(ConvertionUtils.toBase64String(card.getContentSnapshot()));
            assertNotNull(cardContent.getIdentity());
            assertNotNull(cardContent.getCreatedAtTimestamp());
            assertNotNull(cardContent.getIdentity());
            assertNotNull(cardContent.getPublicKey());
            assertNotNull(cardContent.getVersion());
        } catch (CryptoException | VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Search application cards

        try {
            List<Card> cards = cardManager.searchCards("[IDENTITY]");
            assertNotNull(cards);
            assertFalse(cards.isEmpty());

            boolean found = false;
            for (Card card : cards) {
                if (publishedCard.getIdentifier().equals(card.getIdentifier())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Created card should be found by search", found);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        // Make card outdated
        // Prepare raw card to publish
        RawSignedModel cardModelNew = null;
        try {
            cardModelNew = cardManager.generateRawCard(keyPair.getPrivateKey(),
                                                       keyPair.getPublicKey(),
                                                       "[IDENTITY]",
                                                       publishedCard.getIdentifier());
        } catch (CryptoException e) {
            // Handle raw card generation exception here
        }

        try {
            modelSigner.sign(cardModelNew, SERVICE_SIGN, apiKey);
        } catch (CryptoException e) {
            fail(e.getMessage());
        }

        try {
            cardManager.publishCard(cardModelNew);
        } catch (VirgilServiceException | CryptoException e) {
            fail(e.getMessage());
        }
    }

}
