package org.springframework.security.boot.line.authentication;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.line.SpringSecurityLineMessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

/**
 * Line authentication (authentication) processing
 */
@Slf4j
public class LineAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityLineMessageSource.getAccessor();
    private final UserDetailsServiceAdapter userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    public LineAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    /** Indicates whether this provider supports the given authentication class.
     * @param authentication the authentication
     * @return the result
     */
    public boolean supports(Class<?> authentication) {
        return (LineAccessTokenAuthenticationToken.class.isAssignableFrom(authentication));
    }
    
    @Override
    /** Performs authentication for the given authentication request.
     * @param authentication the authentication
     * @return the result
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (log.isDebugEnabled()) {
    		log.debug("Processing authentication request : " + authentication);
		}
    	
    	LineAccessTokenAuthenticationToken token = (LineAccessTokenAuthenticationToken) authentication;
        
        UserDetails ud = getUserDetailsService().loadUserDetails(authentication);
        // User Status Check
        getUserDetailsChecker().check(ud);
        
        LineAccessTokenAuthenticationToken authenticationToken = null;
        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
        	SecurityPrincipal principal = (SecurityPrincipal) ud;
        	principal.setSign(token.getSign());
    		principal.setLongitude(token.getLongitude());
    		principal.setLatitude(token.getLatitude());
        	authenticationToken = new LineAccessTokenAuthenticationToken(ud, token.getAccessToken(), ud.getAuthorities());        	
        } else {
        	authenticationToken = new LineAccessTokenAuthenticationToken(token.getPrincipal(), token.getAccessToken(), ud.getAuthorities());
		}
        authenticationToken.setDetails(authentication.getDetails());
        
        return authenticationToken;
    }

    /** Sets the user details checker.
     * @param userDetailsChecker the userDetailsChecker
     */
    public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	/** Returns the user details checker.
	 * @return the result
	 */
	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	/** Returns the user details service.
	 * @return the result
	 */
	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
}
