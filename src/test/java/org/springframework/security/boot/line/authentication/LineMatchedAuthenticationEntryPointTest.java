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
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link LineMatchedAuthenticationEntryPoint}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("LineMatchedAuthenticationEntryPoint Tests")
class LineMatchedAuthenticationEntryPointTest {

    @Test
    @DisplayName("Instance can be created")
    void testInstantiation() {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
        assertThat(entryPoint).isNotNull();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenExpiredException")
    void testSupportsExpiredException() {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
        assertThat(entryPoint.supports(new LineAccessTokenExpiredException("expired"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenIncorrectException")
    void testSupportsIncorrectException() {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
        assertThat(entryPoint.supports(new LineAccessTokenIncorrectException("incorrect"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenInvalidException")
    void testSupportsInvalidException() {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
        assertThat(entryPoint.supports(new LineAccessTokenInvalidException("invalid"))).isTrue();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenNotFoundException")
    void testSupportsNotFoundException() {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
        assertThat(entryPoint.supports(new LineAccessTokenNotFoundException("not found"))).isTrue();
    }

    @Test
    @DisplayName("supports returns false for other exceptions")
    void testDoesNotSupportOtherExceptions() {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
        AuthenticationException otherException = mock(AuthenticationException.class);
        assertThat(entryPoint.supports(otherException)).isFalse();
    }

    @Test
    @DisplayName("commence handles LineAccessTokenExpiredException")
    void testCommenceExpired() throws Exception {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
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

        entryPoint.commence(request, response, new LineAccessTokenExpiredException("expired"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("commence handles LineAccessTokenIncorrectException")
    void testCommenceIncorrect() throws Exception {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
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

        entryPoint.commence(request, response, new LineAccessTokenIncorrectException("incorrect"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("commence handles LineAccessTokenInvalidException")
    void testCommenceInvalid() throws Exception {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
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

        entryPoint.commence(request, response, new LineAccessTokenInvalidException("invalid"));
        verify(response).setStatus(200);
    }

    @Test
    @DisplayName("commence handles LineAccessTokenNotFoundException")
    void testCommenceNotFound() throws Exception {
        LineMatchedAuthenticationEntryPoint entryPoint = new LineMatchedAuthenticationEntryPoint();
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

        entryPoint.commence(request, response, new LineAccessTokenNotFoundException("not found"));
        verify(response).setStatus(200);
    }
}
