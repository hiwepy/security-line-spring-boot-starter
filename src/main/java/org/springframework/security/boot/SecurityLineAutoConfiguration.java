package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.line.authentication.LineMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.line.authentication.LineMatchedAuthenticationFailureHandler;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityLineProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityLineProperties.class })
public class SecurityLineAutoConfiguration {
	
	@Bean
	@ConditionalOnMissingBean
	public LineMatchedAuthenticationEntryPoint lineMatchedAuthenticationEntryPoint() {
		return new LineMatchedAuthenticationEntryPoint();
	}

	@Bean
	@ConditionalOnMissingBean
	public LineMatchedAuthenticationFailureHandler lineMatchedAuthenticationFailureHandler() {
		return new LineMatchedAuthenticationFailureHandler();
	}

}
