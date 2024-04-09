package com.armorauth.core.converter;

import com.armorauth.data.entity.OAuth2TokenSettings;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.Optional;

public class OAuth2TokenSettingsToTokenSettingsConverter implements Converter<OAuth2TokenSettings, TokenSettings>{
    @Override
    public TokenSettings convert(OAuth2TokenSettings oAuth2TokenSettings) {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Optional.ofNullable(oAuth2TokenSettings.getAccessTokenTimeToLive()).orElse(Duration.ofMinutes(5)))
                .refreshTokenTimeToLive(Optional.ofNullable(oAuth2TokenSettings.getRefreshTokenTimeToLive()).orElse(Duration.ofMinutes(30)))
                .deviceCodeTimeToLive(Optional.ofNullable(oAuth2TokenSettings.getDeviceCodeTimeToLive()).orElse(Duration.ofMinutes(5)))
                .authorizationCodeTimeToLive(Optional.ofNullable(oAuth2TokenSettings.getAuthorizationCodeTimeToLive()).orElse(Duration.ofMinutes(5)))
                .accessTokenFormat(Optional.ofNullable(oAuth2TokenSettings.getTokenFormat())
                        .map(OAuth2TokenFormat::new)
                        .orElse(OAuth2TokenFormat.SELF_CONTAINED))
                .reuseRefreshTokens(oAuth2TokenSettings.getReuseRefreshTokens())
                .idTokenSignatureAlgorithm(Optional.ofNullable(oAuth2TokenSettings.getIdTokenSignatureAlgorithm())
                        .map(SignatureAlgorithm::from)
                        .orElse(SignatureAlgorithm.RS256))
                .build();
    }
}
