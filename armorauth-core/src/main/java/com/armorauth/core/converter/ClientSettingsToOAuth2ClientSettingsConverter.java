package com.armorauth.core.converter;

import com.armorauth.data.entity.OAuth2ClientSettings;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

public class ClientSettingsToOAuth2ClientSettingsConverter implements Converter<ClientSettings, OAuth2ClientSettings> {

    @Override
    public OAuth2ClientSettings convert(ClientSettings clientSettings) {
        OAuth2ClientSettings oAuth2ClientSettings = new OAuth2ClientSettings();
        oAuth2ClientSettings.setRequireProofKey(clientSettings.isRequireProofKey());
        oAuth2ClientSettings.setRequireAuthorizationConsent(clientSettings.isRequireAuthorizationConsent());
        oAuth2ClientSettings.setJwkSetUrl(clientSettings.getJwkSetUrl());
        JwsAlgorithm algorithm = clientSettings.getTokenEndpointAuthenticationSigningAlgorithm();
        if (algorithm != null) {
            oAuth2ClientSettings.setSigningAlgorithm(algorithm.getName());
        }
        return oAuth2ClientSettings;
    }
}
