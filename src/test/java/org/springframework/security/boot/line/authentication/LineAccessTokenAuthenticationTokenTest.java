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
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link LineAccessTokenAuthenticationToken}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("LineAccessTokenAuthenticationToken Tests")
class LineAccessTokenAuthenticationTokenTest {

    @Test
    @DisplayName("Instance can be created via constructor with principal and accessToken")
    void testInstantiation() {
        LineAccessTokenAuthenticationToken instance = new LineAccessTokenAuthenticationToken("principal", "token123");
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Constructor with authorities sets them correctly")
    void testConstructorWithAuthorities() {
        LineAccessTokenAuthenticationToken instance = new LineAccessTokenAuthenticationToken(
                "principal", "token123",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        assertThat(instance).isNotNull();
        assertThat(instance.getAuthorities()).hasSize(1);
    }

    @Test
    @DisplayName("getCredentials returns the access token")
    void testGetCredentials() {
        LineAccessTokenAuthenticationToken instance = new LineAccessTokenAuthenticationToken("principal", "token123");
        assertThat(instance.getCredentials()).isEqualTo("token123");
    }

    @Test
    @DisplayName("getAccessToken returns the access token")
    void testGetAccessToken() {
        LineAccessTokenAuthenticationToken instance = new LineAccessTokenAuthenticationToken("principal", "token123");
        assertThat(instance.getAccessToken()).isEqualTo("token123");
    }

    @Test
    @DisplayName("eraseCredentials clears the access token")
    void testEraseCredentials() {
        LineAccessTokenAuthenticationToken instance = new LineAccessTokenAuthenticationToken("principal", "token123");
        instance.eraseCredentials();
        assertThat(instance.getAccessToken()).isNull();
        assertThat(instance.getCredentials()).isNull();
    }
}
