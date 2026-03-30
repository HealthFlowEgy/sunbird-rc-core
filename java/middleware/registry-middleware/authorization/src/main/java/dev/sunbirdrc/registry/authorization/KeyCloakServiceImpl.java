package dev.sunbirdrc.registry.authorization;

import org.keycloak.RSATokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyCloakServiceImpl {

	private static final Logger logger = LoggerFactory.getLogger(KeyCloakServiceImpl.class);

	private String ssoUrl;
	private String ssoRealm;
	private PublicKey publicKey;

	public KeyCloakServiceImpl(String ssoUrl, String ssoRealm, String publicKeyStr) {
		this.ssoUrl = ssoUrl;
		this.ssoRealm = ssoRealm;
		this.publicKey = toPublicKey(publicKeyStr);
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * This method verifies input JWT access token using RSATokenVerifier of Sunbird
	 * keycloak server
	 *
	 * @param accessToken
	 * @throws VerificationException
	 * @throws Exception
	 */
	public AccessToken verifyToken(String accessToken) throws VerificationException, Exception {
		AccessToken token = RSATokenVerifier.verifyToken(accessToken, publicKey, ssoUrl + "realms/" + ssoRealm, true,
				true);
		logger.debug("Authentication token \n TokenId: {} \t isActive: {} \t isExpired: {} \t", token.getId(),
				token.isActive(), token.isExpired());
		return token;
	}

	/**
	 * This method transforms public key from String to encoded format
	 *
	 * @param publicKeyString
	 * @throws VerificationException
	 * @throws Exception
	 */
	public PublicKey toPublicKey(String publicKeyString) {
		try {
			byte[] publicBytes = Base64.getDecoder().decode(publicKeyString);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new IllegalStateException("Failed to parse public key - cannot start application", e);
		}
	}
}
