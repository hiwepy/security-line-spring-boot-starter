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

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link LineMatchedAuthenticationSuccessHandler}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("LineMatchedAuthenticationSuccessHandler Tests")
class LineMatchedAuthenticationSuccessHandlerTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        LineMatchedAuthenticationSuccessHandler handler = new LineMatchedAuthenticationSuccessHandler(payloadRepository);
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenAuthenticationToken")
    void testSupportsLineToken() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        LineMatchedAuthenticationSuccessHandler handler = new LineMatchedAuthenticationSuccessHandler(payloadRepository);
        LineAccessTokenAuthenticationToken token = new LineAccessTokenAuthenticationToken("principal", "token");
        assertThat(handler.supports(token)).isTrue();
    }

    @Test
    @DisplayName("supports returns false for other token types")
    void testDoesNotSupportOtherTokens() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        LineMatchedAuthenticationSuccessHandler handler = new LineMatchedAuthenticationSuccessHandler(payloadRepository);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "pass");
        assertThat(handler.supports(token)).isFalse();
    }

    @Test
    @DisplayName("getPayloadRepository returns the injected repository")
    void testGetPayloadRepository() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        LineMatchedAuthenticationSuccessHandler handler = new LineMatchedAuthenticationSuccessHandler(payloadRepository);
        assertThat(handler.getPayloadRepository()).isSameAs(payloadRepository);
    }

    @Test
    @DisplayName("setPayloadRepository updates the repository")
    void testSetPayloadRepository() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        LineMatchedAuthenticationSuccessHandler handler = new LineMatchedAuthenticationSuccessHandler(payloadRepository);
        JwtPayloadRepository newRepository = mock(JwtPayloadRepository.class);
        handler.setPayloadRepository(newRepository);
        assertThat(handler.getPayloadRepository()).isSameAs(newRepository);
    }

    @Test
    @DisplayName("isCheckExpiry defaults to false")
    void testCheckExpiryDefault() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        LineMatchedAuthenticationSuccessHandler handler = new LineMatchedAuthenticationSuccessHandler(payloadRepository);
        assertThat(handler.isCheckExpiry()).isFalse();
    }

    @Test
    @DisplayName("setCheckExpiry updates the flag")
    void testSetCheckExpiry() {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        LineMatchedAuthenticationSuccessHandler handler = new LineMatchedAuthenticationSuccessHandler(payloadRepository);
        handler.setCheckExpiry(true);
        assertThat(handler.isCheckExpiry()).isTrue();
    }

    @Test
    @DisplayName("onAuthenticationSuccess handles bound principal with profile payload")
    void testOnAuthenticationSuccessWithBoundPrincipal() throws Exception {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        UserProfilePayload profilePayload = mock(UserProfilePayload.class);
        when(payloadRepository.getProfilePayload(any(), anyBoolean())).thenReturn(profilePayload);

        LineMatchedAuthenticationSuccessHandler handler = new LineMatchedAuthenticationSuccessHandler(payloadRepository);

        SecurityPrincipal principal = mock(SecurityPrincipal.class);
        when(principal.isBound()).thenReturn(true);

        LineAccessTokenAuthenticationToken authentication = new LineAccessTokenAuthenticationToken(
                principal, "token123",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public void write(int b) { outputStream.write(b); }
            @Override
            public boolean isReady() { return true; }
            @Override
            public void setWriteListener(WriteListener listener) {}
        });

        handler.onAuthenticationSuccess(request, response, authentication);
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("onAuthenticationSuccess handles unbound principal")
    void testOnAuthenticationSuccessWithUnboundPrincipal() throws Exception {
        JwtPayloadRepository payloadRepository = mock(JwtPayloadRepository.class);
        LineMatchedAuthenticationSuccessHandler handler = new LineMatchedAuthenticationSuccessHandler(payloadRepository);

        SecurityPrincipal principal = mock(SecurityPrincipal.class);
        when(principal.isBound()).thenReturn(false);
        UserProfilePayload profilePayload = mock(UserProfilePayload.class);
        when(principal.toPayload()).thenReturn(profilePayload);

        LineAccessTokenAuthenticationToken authentication = new LineAccessTokenAuthenticationToken(
                principal, "token123",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public void write(int b) { outputStream.write(b); }
            @Override
            public boolean isReady() { return true; }
            @Override
            public void setWriteListener(WriteListener listener) {}
        });

        handler.onAuthenticationSuccess(request, response, authentication);
        verify(response).setStatus(200);
    }
}
