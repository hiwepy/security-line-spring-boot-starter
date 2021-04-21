package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.line.authentication.LineAuthenticationProvider;
import org.springframework.security.boot.line.authentication.LineMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.line.authentication.LineMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.line.authentication.LineMatchedAuthenticationSuccessHandler;

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
	
	@Bean
	@ConditionalOnMissingBean
	public LineMatchedAuthenticationSuccessHandler lineMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new LineMatchedAuthenticationSuccessHandler(payloadRepository);
	}

	@Bean
	@ConditionalOnMissingBean
	public LineAuthenticationProvider lineAuthenticationProvider(UserDetailsServiceAdapter userDetailsService) {
		return new LineAuthenticationProvider(userDetailsService);
	}

}
