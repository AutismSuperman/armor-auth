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
package com.armorauth.federation.provider;

import com.armorauth.federation.provider.gitee.GiteeAccessTokenRestTemplate;
import com.armorauth.federation.provider.gitee.GiteeFederatedOAuth2Provider;
import com.armorauth.federation.provider.gitee.GiteeOAuth2AuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.provider.qq.QqAccessTokenRestTemplate;
import com.armorauth.federation.provider.qq.QqFederatedOAuth2Provider;
import com.armorauth.federation.provider.qq.QqOAuth2AuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.provider.wechat.WechatAccessTokenRestTemplate;
import com.armorauth.federation.provider.wechat.WechatAuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.provider.wechat.WechatFederatedOAuth2Provider;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DelegateAccessTokenResponseClientTest {

    private final FederatedOAuth2ProviderRegistry providerRegistry = new FederatedOAuth2ProviderRegistry(
            java.util.List.of(
                    new GiteeFederatedOAuth2Provider(),
                    new QqFederatedOAuth2Provider(),
                    new WechatFederatedOAuth2Provider()
            )
    );

    @Test
    void shouldSupportCustomTokenHandlingForGiteeQqAndWechat() {
        FederatedOAuth2Provider gitee = providerRegistry.findProvider("gitee").orElseThrow();
        FederatedOAuth2Provider qq = providerRegistry.findProvider("qq").orElseThrow();
        FederatedOAuth2Provider wechat = providerRegistry.findProvider("wechat").orElseThrow();

        assertThat(new GiteeAccessTokenRestTemplate().supports("gitee")).isTrue();
        assertThat(new GiteeOAuth2AuthorizationCodeGrantRequestConverter().supports("gitee")).isTrue();
        assertThat(gitee.getAccessTokenRestTemplate()).isNotNull();

        assertThat(new QqAccessTokenRestTemplate().supports("qq")).isTrue();
        assertThat(new QqOAuth2AuthorizationCodeGrantRequestConverter().supports("qq")).isTrue();
        assertThat(qq.getOAuth2UserService()).isNotNull();

        assertThat(new WechatAccessTokenRestTemplate().supports("wechat")).isTrue();
        assertThat(new WechatAuthorizationCodeGrantRequestConverter().supports("wechat")).isTrue();
        assertThat(wechat.getAuthorizationRequestConverter()).isNotNull();
    }

    @Test
    void shouldNotTreatGithubAsCustomProvider() {
        assertThat(new GiteeAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new GiteeOAuth2AuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(new QqAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new QqOAuth2AuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(new WechatAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new WechatAuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(providerRegistry.findProvider("github")).isEmpty();
    }

}
