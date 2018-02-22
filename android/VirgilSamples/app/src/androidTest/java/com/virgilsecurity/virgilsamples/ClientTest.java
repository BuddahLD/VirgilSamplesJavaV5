package com.virgilsecurity.virgilsamples;

import android.test.AndroidTestCase;

import com.virgilsecurity.sdk.client.RequestSigner;
import com.virgilsecurity.sdk.client.VirgilClient;
import com.virgilsecurity.sdk.client.VirgilClientContext;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.client.model.CardModel;
import com.virgilsecurity.sdk.client.model.RevocationReason;
import com.virgilsecurity.sdk.client.model.dto.SearchCriteria;
import com.virgilsecurity.sdk.client.requests.PublishCardRequest;
import com.virgilsecurity.sdk.client.requests.RevokeCardRequest;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;

import org.apache.commons.lang.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

/**
 * Created by Andrii Iakovenko on 07.10.16.
 */
public class ClientTest extends AndroidTestCase {

    private static String cardId;

    private Crypto crypto;
    private VirgilClient client;
    private RequestSigner requestSigner;
    private PrivateKey appKey;
    private KeyPair aliceKeys;

    private String CARDS_SERVICE = "";
    private String RO_CARDS_SERVICE = "";
    private String IDENTITY_SERVICE = "";

    private String APP_ID = "{APP_ID}";
    private String APP_BUNDLE = "{APP_BUNDLE}";
    private String APP_TOKEN = "{APP_TOKEN}";
    private String APP_PRIVATE_KEY_PASSWORD = "{APP_PRIVATE_KEY_PASSWORD}";
    private String APP_PRIVATE_KEY = "{APP_PRIVATE_KEY}";

    public void testFlow() throws MalformedURLException {
        crypto = new VirgilCrypto();

        VirgilClientContext ctx = new VirgilClientContext(APP_TOKEN);

        if (StringUtils.isNotBlank(CARDS_SERVICE)) {
            ctx.setCardsServiceURL(new URL(CARDS_SERVICE));
        }

        if (StringUtils.isNotBlank(RO_CARDS_SERVICE)) {
            ctx.setReadOnlyCardsServiceURL(new URL(RO_CARDS_SERVICE));
        }

        if (StringUtils.isNotBlank(IDENTITY_SERVICE)) {
            ctx.setIdentityServiceURL(new URL(IDENTITY_SERVICE));
        }

        client = new VirgilClient(ctx);
        requestSigner = new RequestSigner(crypto);

        appKey = crypto.importPrivateKey(APP_PRIVATE_KEY.getBytes(), APP_PRIVATE_KEY_PASSWORD);
        aliceKeys = crypto.generateKeys();

        // Create card
        byte[] exportedPublicKey = crypto.exportPublicKey(aliceKeys.getPublicKey());
        PublishCardRequest createCardRequest = new PublishCardRequest("alice", "username", exportedPublicKey);

        try {
            requestSigner.selfSign(createCardRequest, aliceKeys.getPrivateKey());
            requestSigner.authoritySign(createCardRequest, APP_ID, appKey);

            CardModel aliceCard = client.publishCard(createCardRequest);

            assertNotNull(aliceCard);
            assertNotNull(aliceCard.getId());
            assertNotNull(aliceCard.getSnapshotModel().getIdentity());
            assertNotNull(aliceCard.getSnapshotModel().getIdentityType());
            assertNotNull(aliceCard.getSnapshotModel().getScope());
            assertNotNull(aliceCard.getMeta().getVersion());

            cardId = aliceCard.getId();
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Get card
        try {
            CardModel card = client.getCard(cardId);
            assertNotNull(card);
            assertNotNull(card.getId());
            assertNotNull(card.getSnapshotModel().getIdentity());
            assertNotNull(card.getSnapshotModel().getIdentityType());
            assertNotNull(card.getSnapshotModel().getScope());
            assertNotNull(card.getMeta().getVersion());
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Search application cards
        SearchCriteria criteria = SearchCriteria.byAppBundle(APP_BUNDLE);

        try {
            List<CardModel> cards = client.searchCards(criteria);
            assertNotNull(cards);
            assertFalse(cards.isEmpty());

            boolean found = false;
            for (CardModel card : cards) {
                if (APP_ID.equals(card.getId())) {
                    found = true;
                    break;
                }
            }
            assertTrue("Created card should be found by search", found);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }

        // Revoke card
        RevokeCardRequest revokeRequest = new RevokeCardRequest(cardId, RevocationReason.UNSPECIFIED);

        requestSigner.selfSign(revokeRequest, aliceKeys.getPrivateKey());
        requestSigner.authoritySign(revokeRequest, APP_ID, appKey);

        try {
            client.revokeCard(revokeRequest);
        } catch (VirgilServiceException e) {
            fail(e.getMessage());
        }
    }

}
