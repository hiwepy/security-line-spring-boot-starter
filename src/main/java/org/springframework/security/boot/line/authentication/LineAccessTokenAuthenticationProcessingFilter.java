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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.AuthenticationProcessingFilter;
import org.springframework.security.boot.line.exception.LineAccessTokenIncorrectException;
import org.springframework.security.boot.line.exception.LineAccessTokenNotFoundException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Line AccessToken 登录授权 (authorization)过滤器
 */
@Slf4j
public class LineAccessTokenAuthenticationProcessingFilter extends AuthenticationProcessingFilter {
	
	/**
	 * Get user profile
	 * https://developers.line.biz/en/reference/line-login/#profile
	 */
	private static String USER_PROFILE_URL = "https://api.line.me/v2/profile";
	
	/**
	 * HTTP Authorization Param, equal to <code>accessToken</code>
	 */
	public static final String AUTHORIZATION_PARAM = "accessToken";
	private ObjectMapper objectMapper = new ObjectMapper();
	private String authorizationParamName = AUTHORIZATION_PARAM;
    private OkHttpClient okhttp3Client;
	
    public LineAccessTokenAuthenticationProcessingFilter(ObjectMapper objectMapper, OkHttpClient okhttp3Client) {
    	super(new AntPathRequestMatcher("/login/line"));
    	this.objectMapper = objectMapper;
    	this.okhttp3Client = okhttp3Client;
    }

    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
 
    	String accessToken = "";
    	
		// Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			LineAccessTokenLoginRequest loginRequest = objectMapper.readValue(request.getReader(), LineAccessTokenLoginRequest.class);
			accessToken = loginRequest.getAccessToken();
		} else {
			accessToken = this.obtainAccessToken(request);
		}
		if (accessToken == null) {
			accessToken = "";
		}
		accessToken = accessToken.trim();
		
		if(StringUtils.isBlank(accessToken)) {
			throw new LineAccessTokenNotFoundException("accessToken not provided");
		}
		
		long start = System.currentTimeMillis();
		LineAccessTokenProfile profile = null;
		try {

            Request request1 = new Request.Builder().url(USER_PROFILE_URL)
					.header("Authorization", "Bearer ".concat(accessToken)).build();
            Response response1 = okhttp3Client.newCall(request1).execute();
            if (response1.isSuccessful()) {
                String content = response1.body().string();
                log.debug("Request Success: code : {}, body : {} , use time : {} ", response1.code(), content, System.currentTimeMillis() - start);
                profile = JSONObject.parseObject(content, LineAccessTokenProfile.class);
            }
            
        } catch (Exception e) {
            log.error("Request Failure : {}, use time : {} ", e.getMessage(), System.currentTimeMillis() - start);
            throw new LineAccessTokenIncorrectException(" Line accessToken Invalid ");
        }
		
		LineAccessTokenAuthenticationToken authRequest = new LineAccessTokenAuthenticationToken(profile, accessToken);
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

}