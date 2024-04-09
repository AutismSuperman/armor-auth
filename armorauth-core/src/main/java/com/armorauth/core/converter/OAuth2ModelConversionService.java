package com.armorauth.core.converter;

import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.convert.support.GenericConversionService;

public class OAuth2ModelConversionService extends GenericConversionService {

    private static volatile OAuth2ModelConversionService sharedInstance;

    private OAuth2ModelConversionService() {
        addConverters(this);
    }


    public static OAuth2ModelConversionService getSharedInstance() {
        OAuth2ModelConversionService sharedInstance = OAuth2ModelConversionService.sharedInstance;
        if (sharedInstance == null) {
            synchronized (OAuth2ModelConversionService.class) {
                sharedInstance = OAuth2ModelConversionService.sharedInstance;
                if (sharedInstance == null) {
                    sharedInstance = new OAuth2ModelConversionService();
                    OAuth2ModelConversionService.sharedInstance = sharedInstance;
                }
            }
        }
        return sharedInstance;
    }


    public static void addConverters(ConverterRegistry converterRegistry) {
        converterRegistry.addConverter(new OAuth2TokenSettingsToTokenSettingsConverter());
        converterRegistry.addConverter(new TokenSettingsToOAuth2TokenSettingsConverter());
        converterRegistry.addConverter(new OAuth2ClientSettingsToClientSettingsConverter());
        converterRegistry.addConverter(new ClientSettingsToOAuth2ClientSettingsConverter());
    }

}
