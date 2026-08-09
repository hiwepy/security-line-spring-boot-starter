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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link LineAccessTokenLoginRequest}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("LineAccessTokenLoginRequest Tests")
class LineAccessTokenLoginRequestTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        LineAccessTokenLoginRequest instance = new LineAccessTokenLoginRequest("token123");
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Constructor with null accessToken")
    void testConstructorWithNull() {
        LineAccessTokenLoginRequest instance = new LineAccessTokenLoginRequest(null);
        assertThat(instance).isNotNull();
        assertThat(instance.getAccessToken()).isNull();
    }

    @Test
    @DisplayName("getAccessToken returns the token set in constructor")
    void testGetAccessToken() {
        LineAccessTokenLoginRequest instance = new LineAccessTokenLoginRequest("token123");
        assertThat(instance.getAccessToken()).isEqualTo("token123");
    }

    @Test
    @DisplayName("setAccessToken updates the token")
    void testSetAccessToken() {
        LineAccessTokenLoginRequest instance = new LineAccessTokenLoginRequest("token123");
        instance.setAccessToken("newToken456");
        assertThat(instance.getAccessToken()).isEqualTo("newToken456");
    }

    @Test
    @DisplayName("setAccessToken with null")
    void testSetAccessTokenNull() {
        LineAccessTokenLoginRequest instance = new LineAccessTokenLoginRequest("token123");
        instance.setAccessToken(null);
        assertThat(instance.getAccessToken()).isNull();
    }
}
