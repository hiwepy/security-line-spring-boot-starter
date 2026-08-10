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
package org.springframework.security.boot.line.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Line AccessToken exception classes.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("Line AccessToken Exception Tests")
class LineAccessTokenExceptionTest {

    @Test
    @DisplayName("LineAccessTokenExpiredException can be created with message")
    void testExpiredExceptionWithMessage() {
        LineAccessTokenExpiredException exception = new LineAccessTokenExpiredException("Token expired");
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Token expired");
    }

    @Test
    @DisplayName("LineAccessTokenExpiredException can be created with message and cause")
    void testExpiredExceptionWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        LineAccessTokenExpiredException exception = new LineAccessTokenExpiredException("Token expired", cause);
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Token expired");
        assertThat(exception.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("LineAccessTokenIncorrectException can be created with message")
    void testIncorrectExceptionWithMessage() {
        LineAccessTokenIncorrectException exception = new LineAccessTokenIncorrectException("Token incorrect");
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Token incorrect");
    }

    @Test
    @DisplayName("LineAccessTokenIncorrectException can be created with message and cause")
    void testIncorrectExceptionWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        LineAccessTokenIncorrectException exception = new LineAccessTokenIncorrectException("Token incorrect", cause);
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Token incorrect");
        assertThat(exception.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("LineAccessTokenInvalidException can be created with message")
    void testInvalidExceptionWithMessage() {
        LineAccessTokenInvalidException exception = new LineAccessTokenInvalidException("Token invalid");
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Token invalid");
    }

    @Test
    @DisplayName("LineAccessTokenInvalidException can be created with message and cause")
    void testInvalidExceptionWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        LineAccessTokenInvalidException exception = new LineAccessTokenInvalidException("Token invalid", cause);
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Token invalid");
        assertThat(exception.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("LineAccessTokenNotFoundException can be created with message")
    void testNotFoundExceptionWithMessage() {
        LineAccessTokenNotFoundException exception = new LineAccessTokenNotFoundException("Token not found");
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Token not found");
    }

    @Test
    @DisplayName("LineAccessTokenNotFoundException can be created with message and cause")
    void testNotFoundExceptionWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("root cause");
        LineAccessTokenNotFoundException exception = new LineAccessTokenNotFoundException("Token not found", cause);
        assertThat(exception).isNotNull();
        assertThat(exception.getMessage()).isEqualTo("Token not found");
        assertThat(exception.getCause()).isSameAs(cause);
    }
}
