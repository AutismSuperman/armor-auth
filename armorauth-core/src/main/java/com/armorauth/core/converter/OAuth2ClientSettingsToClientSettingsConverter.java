package com.armorauth.core.converter;

import com.armorauth.data.entity.OAuth2ClientSettings;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.util.StringUtils;

public class OAuth2ClientSettingsToClientSettingsConverter implements Converter<OAuth2ClientSettings, ClientSettings> {
    @Override
    public ClientSettings convert(OAuth2ClientSettings oAuth2ClientSettings) {
        ClientSettings.Builder builder = ClientSettings.builder()
                .requireProofKey(oAuth2ClientSettings.getRequireProofKey())
                .requireAuthorizationConsent(oAuth2ClientSettings.getRequireAuthorizationConsent());
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.from(oAuth2ClientSettings.getSigningAlgorithm());
        JwsAlgorithm jwsAlgorithm = signatureAlgorithm == null ? MacAlgorithm.from(oAuth2ClientSettings.getSigningAlgorithm()) : signatureAlgorithm;
        if (jwsAlgorithm != null) {
            builder.tokenEndpointAuthenticationSigningAlgorithm(jwsAlgorithm);
        }
        if (StringUtils.hasText(oAuth2ClientSettings.getJwkSetUrl())) {
            builder.jwkSetUrl(oAuth2ClientSettings.getJwkSetUrl());
        }
        return builder.build();
    }
}
