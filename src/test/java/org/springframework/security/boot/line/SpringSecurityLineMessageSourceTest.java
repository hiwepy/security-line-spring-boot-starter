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
package org.springframework.security.boot.line;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.support.MessageSourceAccessor;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SpringSecurityLineMessageSource}.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@DisplayName("SpringSecurityLineMessageSource Tests")
class SpringSecurityLineMessageSourceTest {

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        SpringSecurityLineMessageSource instance = new SpringSecurityLineMessageSource();
        assertThat(instance).isNotNull();
    }

    @Test
    @DisplayName("getAccessor returns a non-null MessageSourceAccessor")
    void testGetAccessor() {
        MessageSourceAccessor accessor = SpringSecurityLineMessageSource.getAccessor();
        assertThat(accessor).isNotNull();
    }

    @Test
    @DisplayName("getAccessor returns a new instance each time")
    void testGetAccessorReturnsNewInstance() {
        MessageSourceAccessor accessor1 = SpringSecurityLineMessageSource.getAccessor();
        MessageSourceAccessor accessor2 = SpringSecurityLineMessageSource.getAccessor();
        assertThat(accessor1).isNotSameAs(accessor2);
    }
}
