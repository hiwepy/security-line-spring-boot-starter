package org.springframework.security.boot.line.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Line AccessToken loginauthenticationbinding objectModel
 * 
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class LineAccessTokenLoginRequest {

	/**
	 * Google AccessToken
	 */
	private String accessToken;

	/**
	 * Constructs a new line access token login request instance.
	 *
	 */
	@JsonCreator
	public LineAccessTokenLoginRequest(@JsonProperty("accessToken") String accessToken) {
		this.accessToken = accessToken;
	}

	/** Returns the access token.
	 * @return the result
	 */
	public String getAccessToken() {
		return accessToken;
	}

	/** Sets the access token.
	 * @param accessToken the accessToken
	 */
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

}
