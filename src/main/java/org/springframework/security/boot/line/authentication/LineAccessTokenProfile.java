package org.springframework.security.boot.line.authentication;

import lombok.Data;

/**
 * https://developers.line.biz/en/reference/line-login/#get-user-profile
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
@Data
public class LineAccessTokenProfile {
	
	/**
	 * User ID
	 */
	private String userId;
	/**
	 * User's display name
	 */
	private String displayName;
	/**
	 * Profile image URL. This is an HTTPS URL. It's only included in the response if the user has set a profile image.
	 *
	 * Profile image thumbnails:
	 *
	 * You can get a thumbnail version of a user's profile image by appending any 
	 * of the following suffixes to their profile image URL.
	 * 
	 * Suffix 	Thumbnail size
	 * /large 	200 x 200
	 * /small 	51 x 51
	 * 
	 * Example: https://profile.line-scdn.net/abcdefghijklmn/large
	 * 
	 */
	private String pictureUrl;
	/**
	 * User's status message. Not included in the response if the user doesn't have a status message.
	 */
	private String statusMessage;
	
}
