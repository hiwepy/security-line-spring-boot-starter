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
 * Unit tests for {@link LineAccessTokenProfile}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("LineAccessTokenProfile Tests")
class LineAccessTokenProfileTest {

    @Test
    @DisplayName("Instance can be created via default constructor")
    void testInstantiation() {
        LineAccessTokenProfile instance = new LineAccessTokenProfile();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("Getters and setters work correctly")
    void testGettersAndSetters() {
        LineAccessTokenProfile profile = new LineAccessTokenProfile();
        profile.setUserId("U123456");
        profile.setDisplayName("Test User");
        profile.setPictureUrl("https://example.com/pic.jpg");
        profile.setStatusMessage("Hello");

        assertThat(profile.getUserId()).isEqualTo("U123456");
        assertThat(profile.getDisplayName()).isEqualTo("Test User");
        assertThat(profile.getPictureUrl()).isEqualTo("https://example.com/pic.jpg");
        assertThat(profile.getStatusMessage()).isEqualTo("Hello");
    }

    @Test
    @DisplayName("toString contains all fields")
    void testToString() {
        LineAccessTokenProfile profile = new LineAccessTokenProfile();
        profile.setUserId("U123456");
        profile.setDisplayName("Test User");

        String str = profile.toString();
        assertThat(str).contains("U123456");
        assertThat(str).contains("Test User");
    }

    @Test
    @DisplayName("equals and hashCode work correctly")
    void testEqualsAndHashCode() {
        LineAccessTokenProfile profile1 = new LineAccessTokenProfile();
        profile1.setUserId("U123456");
        profile1.setDisplayName("Test User");

        LineAccessTokenProfile profile2 = new LineAccessTokenProfile();
        profile2.setUserId("U123456");
        profile2.setDisplayName("Test User");

        assertThat(profile1).isEqualTo(profile2);
        assertThat(profile1.hashCode()).isEqualTo(profile2.hashCode());
    }

    @Test
    @DisplayName("equals returns false for different profiles")
    void testNotEquals() {
        LineAccessTokenProfile profile1 = new LineAccessTokenProfile();
        profile1.setUserId("U123456");

        LineAccessTokenProfile profile2 = new LineAccessTokenProfile();
        profile2.setUserId("U789012");

        assertThat(profile1).isNotEqualTo(profile2);
    }
}
