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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.line.exception.LineAccessTokenExpiredException;
import org.springframework.security.boot.line.exception.LineAccessTokenIncorrectException;
import org.springframework.security.boot.line.exception.LineAccessTokenInvalidException;
import org.springframework.security.boot.line.exception.LineAccessTokenNotFoundException;
import org.springframework.security.core.AuthenticationException;

import java.io.ByteArrayOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link LineMatchedAuthenticationFailureHandler}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("LineMatchedAuthenticationFailureHandler Tests")
class LineMatchedAuthenticationFailureHandlerTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        assertThat(handler).isNotNull();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenExpiredException")
    void testSupportsExpiredException() {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        assertThat(handler.supports(new LineAccessTokenExpiredException("expired"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenIncorrectException")
    void testSupportsIncorrectException() {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        assertThat(handler.supports(new LineAccessTokenIncorrectException("incorrect"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenInvalidException")
    void testSupportsInvalidException() {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        assertThat(handler.supports(new LineAccessTokenInvalidException("invalid"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenNotFoundException")
    void testSupportsNotFoundException() {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        assertThat(handler.supports(new LineAccessTokenNotFoundException("not found"))).isTrue();
    }

    @Test
    @DisplayName("supports returns false for other exceptions")
    void testDoesNotSupportOtherExceptions() {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        AuthenticationException otherException = mock(AuthenticationException.class);
        assertThat(handler.supports(otherException)).isFalse();
    }

    @Test
    @DisplayName("onAuthenticationFailure handles LineAccessTokenExpiredException")
    void testOnFailureExpired() throws Exception {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) { outputStream.write(b); }
            @Override
            public boolean isReady() { return true; }
            @Override
            public void setWriteListener(jakarta.servlet.WriteListener listener) {}
        });

        handler.onAuthenticationFailure(request, response, new LineAccessTokenExpiredException("expired"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("onAuthenticationFailure handles LineAccessTokenIncorrectException")
    void testOnFailureIncorrect() throws Exception {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) { outputStream.write(b); }
            @Override
            public boolean isReady() { return true; }
            @Override
            public void setWriteListener(jakarta.servlet.WriteListener listener) {}
        });

        handler.onAuthenticationFailure(request, response, new LineAccessTokenIncorrectException("incorrect"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("onAuthenticationFailure handles LineAccessTokenInvalidException")
    void testOnFailureInvalid() throws Exception {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) { outputStream.write(b); }
            @Override
            public boolean isReady() { return true; }
            @Override
            public void setWriteListener(jakarta.servlet.WriteListener listener) {}
        });

        handler.onAuthenticationFailure(request, response, new LineAccessTokenInvalidException("invalid"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("onAuthenticationFailure handles LineAccessTokenNotFoundException")
    void testOnFailureNotFound() throws Exception {
        LineMatchedAuthenticationFailureHandler handler = new LineMatchedAuthenticationFailureHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        when(response.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) { outputStream.write(b); }
            @Override
            public boolean isReady() { return true; }
            @Override
            public void setWriteListener(jakarta.servlet.WriteListener listener) {}
        });

        handler.onAuthenticationFailure(request, response, new LineAccessTokenNotFoundException("not found"));
        verify(response).setStatus(200);
    }
}
