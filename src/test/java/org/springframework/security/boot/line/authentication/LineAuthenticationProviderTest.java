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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

import java.util.Collection;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link LineAuthenticationProvider}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("LineAuthenticationProvider Tests")
class LineAuthenticationProviderTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        LineAuthenticationProvider provider = new LineAuthenticationProvider(userDetailsService);
        assertThat(provider).isNotNull();
    }

    @Test
    @DisplayName("supports returns true for LineAccessTokenAuthenticationToken")
    void testSupportsLineToken() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        LineAuthenticationProvider provider = new LineAuthenticationProvider(userDetailsService);
        assertThat(provider.supports(LineAccessTokenAuthenticationToken.class)).isTrue();
    }

    @Test
    @DisplayName("supports returns false for other token types")
    void testDoesNotSupportOtherTokens() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        LineAuthenticationProvider provider = new LineAuthenticationProvider(userDetailsService);
        assertThat(provider.supports(UsernamePasswordAuthenticationToken.class)).isFalse();
    }

    @Test
    @DisplayName("authenticate throws exception when authentication is null")
    void testAuthenticateWithNull() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        LineAuthenticationProvider provider = new LineAuthenticationProvider(userDetailsService);
        assertThatThrownBy(() -> provider.authenticate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("getUserDetailsService returns the injected service")
    void testGetUserDetailsService() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        LineAuthenticationProvider provider = new LineAuthenticationProvider(userDetailsService);
        assertThat(provider.getUserDetailsService()).isSameAs(userDetailsService);
    }

    @Test
    @DisplayName("getUserDetailsChecker returns non-null default")
    void testGetUserDetailsChecker() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        LineAuthenticationProvider provider = new LineAuthenticationProvider(userDetailsService);
        assertThat(provider.getUserDetailsChecker()).isNotNull();
    }

    @Test
    @DisplayName("setUserDetailsChecker updates the checker")
    void testSetUserDetailsChecker() {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        LineAuthenticationProvider provider = new LineAuthenticationProvider(userDetailsService);
        UserDetailsChecker checker = mock(UserDetailsChecker.class);
        provider.setUserDetailsChecker(checker);
        assertThat(provider.getUserDetailsChecker()).isSameAs(checker);
    }

    @Test
    @DisplayName("authenticate returns authenticated token for SecurityPrincipal")
    void testAuthenticateWithSecurityPrincipal() throws Exception {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        SecurityPrincipal principal = mock(SecurityPrincipal.class);
        Collection<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        when(principal.getAuthorities()).thenReturn((Collection) authorities);
        when(userDetailsService.loadUserDetails((Authentication) any())).thenReturn(principal);

        LineAuthenticationProvider provider = new LineAuthenticationProvider(userDetailsService);
        // Replace the userDetailsChecker with a no-op to skip account status checks
        provider.setUserDetailsChecker(mock(UserDetailsChecker.class));

        LineAccessTokenAuthenticationToken authRequest = new LineAccessTokenAuthenticationToken("principal", "token123");
        Authentication result = provider.authenticate(authRequest);

        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
    }

    @Test
    @DisplayName("authenticate returns authenticated token for regular UserDetails")
    void testAuthenticateWithRegularUserDetails() throws Exception {
        UserDetailsServiceAdapter userDetailsService = mock(UserDetailsServiceAdapter.class);
        UserDetails userDetails = mock(UserDetails.class);
        Collection<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        when(userDetails.getAuthorities()).thenReturn((Collection) authorities);
        when(userDetailsService.loadUserDetails((Authentication) any())).thenReturn(userDetails);

        LineAuthenticationProvider provider = new LineAuthenticationProvider(userDetailsService);
        // Replace the userDetailsChecker with a no-op to skip account status checks
        provider.setUserDetailsChecker(mock(UserDetailsChecker.class));

        LineAccessTokenAuthenticationToken authRequest = new LineAccessTokenAuthenticationToken("principal", "token123");
        Authentication result = provider.authenticate(authRequest);

        assertThat(result).isNotNull();
        assertThat(result.isAuthenticated()).isTrue();
    }
}
