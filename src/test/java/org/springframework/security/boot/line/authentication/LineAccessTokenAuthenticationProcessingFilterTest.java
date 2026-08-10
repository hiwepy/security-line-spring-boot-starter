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

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import okhttp3.OkHttpClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link LineAccessTokenAuthenticationProcessingFilter}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("LineAccessTokenAuthenticationProcessingFilter Tests")
class LineAccessTokenAuthenticationProcessingFilterTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        LineAccessTokenAuthenticationProcessingFilter instance = new LineAccessTokenAuthenticationProcessingFilter(null, null);
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Instance can be created with ObjectMapper and OkHttpClient")
    void testInstantiationWithDependencies() {
        ObjectMapper objectMapper = new ObjectMapper();
        OkHttpClient client = new OkHttpClient();
        LineAccessTokenAuthenticationProcessingFilter instance = new LineAccessTokenAuthenticationProcessingFilter(objectMapper, client);
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("AUTHORIZATION_PARAM constant has correct value")
    void testAuthorizationParam() {
        assertThat(LineAccessTokenAuthenticationProcessingFilter.AUTHORIZATION_PARAM).isEqualTo("accessToken");
    }

    @Test
    @DisplayName("getAuthorizationParamName returns default value")
    void testGetAuthorizationParamName() {
        LineAccessTokenAuthenticationProcessingFilter instance = new LineAccessTokenAuthenticationProcessingFilter(null, null);
        assertThat(instance.getAuthorizationParamName()).isEqualTo("accessToken");
    }

    @Test
    @DisplayName("setAuthorizationParamName updates the param name")
    void testSetAuthorizationParamName() {
        LineAccessTokenAuthenticationProcessingFilter instance = new LineAccessTokenAuthenticationProcessingFilter(null, null);
        instance.setAuthorizationParamName("token");
        assertThat(instance.getAuthorizationParamName()).isEqualTo("token");
    }

    @Test
    @DisplayName("obtainAccessToken extracts token from request parameter")
    void testObtainAccessToken() {
        LineAccessTokenAuthenticationProcessingFilter instance = new LineAccessTokenAuthenticationProcessingFilter(null, null);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("accessToken")).thenReturn("testToken123");

        // Use reflection to call protected method
        try {
            java.lang.reflect.Method method = LineAccessTokenAuthenticationProcessingFilter.class.getDeclaredMethod("obtainAccessToken", HttpServletRequest.class);
            method.setAccessible(true);
            String result = (String) method.invoke(instance, request);
            assertThat(result).isEqualTo("testToken123");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("obtainAccessToken returns null when parameter is absent")
    void testObtainAccessTokenNull() {
        LineAccessTokenAuthenticationProcessingFilter instance = new LineAccessTokenAuthenticationProcessingFilter(null, null);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("accessToken")).thenReturn(null);

        try {
            java.lang.reflect.Method method = LineAccessTokenAuthenticationProcessingFilter.class.getDeclaredMethod("obtainAccessToken", HttpServletRequest.class);
            method.setAccessible(true);
            String result = (String) method.invoke(instance, request);
            assertThat(result).isNull();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("setDetails calls authenticationDetailsSource")
    void testSetDetails() {
        LineAccessTokenAuthenticationProcessingFilter instance = new LineAccessTokenAuthenticationProcessingFilter(null, null);
        HttpServletRequest request = mock(HttpServletRequest.class);
        AbstractAuthenticationToken authRequest = mock(AbstractAuthenticationToken.class);

        try {
            java.lang.reflect.Method method = LineAccessTokenAuthenticationProcessingFilter.class.getDeclaredMethod("setDetails", HttpServletRequest.class, AbstractAuthenticationToken.class);
            method.setAccessible(true);
            method.invoke(instance, request, authRequest);
            verify(authRequest).setDetails(any());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
