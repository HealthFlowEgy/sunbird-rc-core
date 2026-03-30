package dev.sunbirdrc.registry.authorization;

import dev.sunbirdrc.pojos.APIMessage;
import dev.sunbirdrc.pojos.SunbirdRCInstrumentation;
import dev.sunbirdrc.registry.authorization.pojos.AuthInfo;
import dev.sunbirdrc.registry.middleware.Middleware;
import dev.sunbirdrc.registry.middleware.MiddlewareHaltException;
import dev.sunbirdrc.registry.middleware.util.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AuthorizationFilter implements Middleware {

	private static final String TOKEN_IS_MISSING = "Authentication header is missing";
	private static final String VERIFICATION_EXCEPTION = "Authentication token is invalid";
	private static final Logger logger = LoggerFactory.getLogger(AuthorizationFilter.class);
	private KeyCloakServiceImpl keyCloakServiceImpl;
	@Autowired
	private SunbirdRCInstrumentation watch;

	public AuthorizationFilter() {
	}

	public AuthorizationFilter(KeyCloakServiceImpl keyCloakServiceImpl) {
		this.keyCloakServiceImpl = keyCloakServiceImpl;
	}

	/**
	 * This method validates JWT access token against Sunbird Keycloak server and
	 * sets the valid access token to a map object
	 * 
	 * @param apiMessage
	 * @throws MiddlewareHaltException
	 */
	@Override
	public boolean execute(APIMessage apiMessage) throws MiddlewareHaltException {
		try {
			Map<String, Object> mapObject = apiMessage.getRequestWrapper().getRequestHeaderMap();
			Object tokenObject = mapObject.get(Constants.TOKEN_OBJECT);

			if (tokenObject == null || tokenObject.toString().trim().isEmpty()) {
				throw new MiddlewareHaltException(TOKEN_IS_MISSING);
			}
			String token = tokenObject.toString();
			watch.start("KeycloakServiceImpl.verifyToken");
			AccessToken accessToken = keyCloakServiceImpl.verifyToken(token);
			watch.stop("KeycloakServiceImpl.verifyToken");
			String userId = accessToken.getSubject();

			if (!userId.trim().isEmpty()) {
				apiMessage.setUserID(userId);
				if (mapObject.containsKey("userName")) {
					logger.debug("Access token for user {} verified successfully with KeyCloak server !",
							mapObject.get("userName"));
				} else {
					logger.debug("Access token verified successfully with KeyCloak server !");
				}
				AuthInfo authInfo = extractAuthInfoFromToken(accessToken);
				if (authInfo.getSub() == null || authInfo.getAud() == null || authInfo.getName() == null) {
					throw new MiddlewareHaltException(VERIFICATION_EXCEPTION);
				}
				List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

				authorityList.add(new SimpleGrantedAuthority(authInfo.getAud()));
				AuthorizationToken authorizationToken = new AuthorizationToken(authInfo, authorityList);
				SecurityContextHolder.getContext().setAuthentication(authorizationToken);
			} else {
				throw new MiddlewareHaltException(VERIFICATION_EXCEPTION);
			}
		} catch (Exception e) {
			logger.error("AuthorizationFilter: MiddlewareHaltException !", e);
			throw new MiddlewareHaltException(VERIFICATION_EXCEPTION);
		}
		return true;
	}

	/**
	 * This method extracts Authorisation information, i.e. AuthInfo from an
	 * already-verified AccessToken, avoiding a redundant second parse of the JWT.
	 *
	 * @param accessToken the verified Keycloak AccessToken
	 */
	public AuthInfo extractAuthInfoFromToken(AccessToken accessToken) {
		AuthInfo authInfo = new AuthInfo();
		if (accessToken.getIssuedFor() != null) {
			authInfo.setAud(accessToken.getIssuedFor());
		}
		if (accessToken.getSubject() != null) {
			authInfo.setSub(accessToken.getSubject());
		}
		if (accessToken.getPreferredUsername() != null) {
			authInfo.setName(accessToken.getPreferredUsername());
		}
		return authInfo;
	}

}
