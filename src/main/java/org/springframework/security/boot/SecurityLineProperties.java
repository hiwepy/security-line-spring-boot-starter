package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityLineProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityLineProperties {

	public static final String PREFIX = "spring.security.line";

	/** Whether Enable Line AccessToken Authentication. */
	private boolean enabled = false;

}
