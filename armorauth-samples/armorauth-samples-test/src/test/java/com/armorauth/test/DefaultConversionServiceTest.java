package com.armorauth.test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.lang.Nullable;

import java.util.Set;

public class DefaultConversionServiceTest {

    public static void main(String[] args) {
        ConversionService conversionService = new ConversionService();
        Boolean aTrue = conversionService.convert("true", Boolean.class);

    }


    static class ConversionService extends GenericConversionService {

        public ConversionService() {
            addDefaultConverters(this);
        }

        public static void addDefaultConverters(ConverterRegistry converterRegistry) {
            converterRegistry.addConverter(new StringToBooleanConverter());
        }

    }


    static class StringToBooleanConverter implements Converter<String, Boolean> {

        private static final Set<String> trueValues = Set.of("true", "on", "yes", "1");

        private static final Set<String> falseValues = Set.of("false", "off", "no", "0");


        @Override
        @Nullable
        public Boolean convert(String source) {
            String value = source.trim();
            if (value.isEmpty()) {
                return null;
            }
            value = value.toLowerCase();
            if (trueValues.contains(value)) {
                return Boolean.TRUE;
            } else if (falseValues.contains(value)) {
                return Boolean.FALSE;
            } else {
                throw new IllegalArgumentException("Invalid boolean value '" + source + "'");
            }
        }

    }




}
