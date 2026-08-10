package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
/** Configuration properties for Line.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

@ConfigurationProperties(prefix = SecurityLineProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityLineProperties {

	public static final String PREFIX = "spring.security.line";

	/** Whether Enable Line AccessToken Authentication. */
	private boolean enabled = false;

}
