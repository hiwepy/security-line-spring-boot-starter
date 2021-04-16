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
package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.line.authentication.LineAccessTokenAuthenticationProcessingFilter;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(SecurityLineAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityLineAuthcProperties extends SecurityAuthcProperties {

	public static final String PREFIX = "spring.security.line.authc";

	/** Authorization Path Pattern */
	private String pathPattern = "/login/line";
	
	/** the token parameter name. Defaults to "token". */
	private String authorizationParamName = LineAccessTokenAuthenticationProcessingFilter.AUTHORIZATION_PARAM;

	private String clientId;

}
