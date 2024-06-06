package com.armorauth.federation.core.user;

import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface ExtendedOAuth2UserService<R extends OAuth2UserRequest, U extends OAuth2User> extends OAuth2UserService<R, U> {

    /**
     * @param registrationId the registration identifier
     */
    boolean supports(String registrationId);
}
