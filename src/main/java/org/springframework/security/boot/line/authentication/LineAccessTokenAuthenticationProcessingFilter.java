/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.line.authentication;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Objects;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.AuthenticationProcessingFilter;
import org.springframework.security.boot.line.exception.LineAcceccTokenNotFoundException;
import org.springframework.security.boot.line.exception.LineAccessTokenVerifierException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;

/**
 * Line AccessToken 登录授权 (authorization)过滤器
 */
public class LineAccessTokenAuthenticationProcessingFilter extends AuthenticationProcessingFilter {

	/**
	 * HTTP Authorization Param, equal to <code>accessToken</code>
	 */
	public static final String AUTHORIZATION_PARAM = "accessToken";
	private ObjectMapper objectMapper = new ObjectMapper();
	private HttpTransport transport = new NetHttpTransport();
	private JsonFactory jsonFactory = new GsonFactory();
	private String authorizationParamName = AUTHORIZATION_PARAM;
	private String clientId;
	
    public LineAccessTokenAuthenticationProcessingFilter(ObjectMapper objectMapper) {
    	super(new AntPathRequestMatcher("/login/google"));
    	this.objectMapper = objectMapper;
    }

    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
 
    	String idTokenString = "";
    	
		// Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			
			LineAccessTokenLoginRequest loginRequest = objectMapper.readValue(request.getReader(), LineAccessTokenLoginRequest.class);
			idTokenString = loginRequest.getAccessToken();

		} else {
			
			idTokenString = this.obtainAccessToken(request);
	 		
		}

		if (idTokenString == null) {
			idTokenString = "";
		}
		
		idTokenString = idTokenString.trim();
		
		if(StringUtils.isBlank(idTokenString)) {
			throw new LineAcceccTokenNotFoundException("accessToken not provided");
		}
		
		try {
			
			GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder( transport, jsonFactory)
			    // Specify the CLIENT_ID of the app that accesses the backend:
			    .setAudience(Collections.singletonList(clientId))
			    // Or, if multiple clients access the backend:
			    //.setAudience(Arrays.asList(CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3))
			    .build();

			GoogleIdToken idToken = verifier.verify(idTokenString);
			if (Objects.isNull(idToken)) {
				throw new LineAccessTokenVerifierException(" Google Id Token Invalid ");
			}
			
			LineAccessTokenAuthenticationToken authRequest = new LineAccessTokenAuthenticationToken(idToken, idTokenString);
			authRequest.setAppId(this.obtainAppId(request));
			authRequest.setAppChannel(this.obtainAppChannel(request));
			authRequest.setAppVersion(this.obtainAppVersion(request));
			authRequest.setUid(this.obtainUid(request));
			authRequest.setLongitude(this.obtainLongitude(request));
			authRequest.setLatitude(this.obtainLatitude(request));
			authRequest.setSign(this.obtainSign(request));
			
			// Allow subclasses to set the "details" property
			setDetails(request, authRequest);

			return this.getAuthenticationManager().authenticate(authRequest);
			
		} catch (GeneralSecurityException e) {
			throw new LineAccessTokenVerifierException(" Google Id Token Verifier Exception : ", e);
		}

    }
    
	protected String obtainAccessToken(HttpServletRequest request) {
		// 从参数中获取token
		String token = request.getParameter(getAuthorizationParamName());
		return token;
	}

	protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	public String getAuthorizationParamName() {
		return authorizationParamName;
	}

	public void setAuthorizationParamName(String authorizationParamName) {
		this.authorizationParamName = authorizationParamName;
	}

	public HttpTransport getTransport() {
		return transport;
	}

	public void setTransport(HttpTransport transport) {
		this.transport = transport;
	}

	public JsonFactory getJsonFactory() {
		return jsonFactory;
	}

	public void setJsonFactory(JsonFactory jsonFactory) {
		this.jsonFactory = jsonFactory;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

}