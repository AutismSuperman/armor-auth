package com.armorauth.core.converter;

import com.armorauth.data.entity.OAuth2TokenSettings;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

public class TokenSettingsToOAuth2TokenSettingsConverter implements Converter<TokenSettings, OAuth2TokenSettings>{
    @Override
    public OAuth2TokenSettings convert(TokenSettings tokenSettings) {
        OAuth2TokenSettings oAuth2TokenSettings = new OAuth2TokenSettings();
        oAuth2TokenSettings.setAccessTokenTimeToLive(tokenSettings.getAccessTokenTimeToLive());
        oAuth2TokenSettings.setRefreshTokenTimeToLive(tokenSettings.getRefreshTokenTimeToLive());
        oAuth2TokenSettings.setAuthorizationCodeTimeToLive(tokenSettings.getAuthorizationCodeTimeToLive());
        oAuth2TokenSettings.setDeviceCodeTimeToLive(tokenSettings.getDeviceCodeTimeToLive());
        oAuth2TokenSettings.setTokenFormat(tokenSettings.getAccessTokenFormat().getValue());
        oAuth2TokenSettings.setReuseRefreshTokens(tokenSettings.isReuseRefreshTokens());
        oAuth2TokenSettings.setIdTokenSignatureAlgorithm(tokenSettings.getIdTokenSignatureAlgorithm().getName());
        return oAuth2TokenSettings;
    }
}
