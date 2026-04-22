/*
 * Copyright (c) 2023-present ArmorAuth. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.armorauth.federation.provider.alipay;

import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

final class AlipaySupport {

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private AlipaySupport() {
    }

    static Map<String, String> gatewayParameters(ClientRegistration clientRegistration, String method) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("app_id", clientRegistration.getClientId());
        parameters.put("method", method);
        parameters.put("format", "JSON");
        parameters.put("charset", "utf-8");
        parameters.put("sign_type", "RSA2");
        parameters.put("timestamp", TIMESTAMP_FORMATTER.format(LocalDateTime.now()));
        parameters.put("version", "1.0");
        return parameters;
    }

    static Map<String, String> sign(Map<String, String> parameters, ClientRegistration clientRegistration) {
        Map<String, String> signedParameters = new LinkedHashMap<>(parameters);
        signedParameters.put("sign", AlipaySigner.sign(signedParameters, clientRegistration.getClientSecret()));
        return signedParameters;
    }

}
