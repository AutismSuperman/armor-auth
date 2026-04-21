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
package com.armorauth.federation.provider.wechat;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import static org.assertj.core.api.Assertions.assertThat;

class WechatAuthorizationRequestConverterTest {

    @Test
    void shouldReplaceClientIdWithAppIdAndAppendWechatFragment() {
        WechatAuthorizationRequestConverter converter = new WechatAuthorizationRequestConverter();
        OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://open.weixin.qq.com/connect/qrconnect")
                .clientId("APP_ID")
                .redirectUri("https://example.com/callback")
                .state("STATE")
                .scope("snsapi_login");

        converter.convert(builder);
        OAuth2AuthorizationRequest request = builder.build();

        assertThat(request.getAuthorizationRequestUri()).contains("#wechat_redirect");
        assertThat(request.getAuthorizationRequestUri()).contains("appid=APP_ID");
        assertThat(request.getAuthorizationRequestUri()).doesNotContain("client_id=");
    }

}
