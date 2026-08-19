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
/** Auto-configuration for Security Line.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityLineProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityLineProperties.class })
public class SecurityLineAutoConfiguration {
	
	@Bean
	@ConditionalOnMissingBean
	/** Creates a line matched authentication entry point bean.
	 * @return the result
	 */
	public LineMatchedAuthenticationEntryPoint lineMatchedAuthenticationEntryPoint() {
		return new LineMatchedAuthenticationEntryPoint();
	}

	/**
	 * line Matched Authentication Failure Handler.
	 *
	 * @return the result
	 */
	@Bean
	@ConditionalOnMissingBean
	public LineMatchedAuthenticationFailureHandler lineMatchedAuthenticationFailureHandler() {
		return new LineMatchedAuthenticationFailureHandler();
	}
	
	/**
	 * line Matched Authentication Success Handler.
	 *
	 * @param payloadRepository the payload repository
	 * @return the result
	 */
	@Bean
	@ConditionalOnMissingBean
	public LineMatchedAuthenticationSuccessHandler lineMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new LineMatchedAuthenticationSuccessHandler(payloadRepository);
	}

	@Bean
	@ConditionalOnMissingBean
	/** Creates a line authentication provider bean.
	 * @param userDetailsService the userDetailsService
	 * @return the result
	 */
	public LineAuthenticationProvider lineAuthenticationProvider(UserDetailsServiceAdapter userDetailsService) {
		return new LineAuthenticationProvider(userDetailsService);
	}

}
