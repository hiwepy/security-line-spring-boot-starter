package org.springframework.security.boot.line.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.line.SpringSecurityLineMessageSource;
import org.springframework.security.boot.line.exception.LineAccessTokenExpiredException;
import org.springframework.security.boot.line.exception.LineAccessTokenIncorrectException;
import org.springframework.security.boot.line.exception.LineAccessTokenInvalidException;
import org.springframework.security.boot.line.exception.LineAccessTokenNotFoundException;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

import com.alibaba.fastjson.JSONObject;

/**
 * Line AccessToken 认证请求失败后的处理实现
 */
public class LineMatchedAuthenticationFailureHandler implements MatchedAuthenticationFailureHandler {

	protected MessageSourceAccessor messages = SpringSecurityLineMessageSource.getAccessor();

	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), LineAccessTokenExpiredException.class,
				LineAccessTokenIncorrectException.class, LineAccessTokenInvalidException.class,
				LineAccessTokenNotFoundException.class );
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {

		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());

		if (e instanceof LineAccessTokenExpiredException) {
			JSONObject.writeJSONString(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED.getMsgKey(), e.getMessage())));
		} else if (e instanceof LineAccessTokenIncorrectException) {
			JSONObject.writeJSONString(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT.getMsgKey(), e.getMessage())));
		} else if (e instanceof LineAccessTokenInvalidException) {
			JSONObject.writeJSONString(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_INVALID.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_INVALID.getMsgKey(), e.getMessage())));
		} else if (e instanceof LineAccessTokenNotFoundException) {
			JSONObject.writeJSONString(response.getOutputStream(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED.getMsgKey(), e.getMessage())));
		}

	}

}
