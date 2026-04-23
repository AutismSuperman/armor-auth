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
import com.armorauth.federation.provider.alipay.AlipayAccessTokenRestTemplate;
import com.armorauth.federation.provider.alipay.AlipayAuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.provider.alipay.AlipayFederatedOAuth2Provider;
import com.armorauth.federation.provider.douyin.DouyinAccessTokenRestTemplate;
import com.armorauth.federation.provider.douyin.DouyinAuthorizationRequestConverter;
import com.armorauth.federation.provider.douyin.DouyinAuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.provider.douyin.DouyinFederatedOAuth2Provider;
import com.armorauth.federation.provider.dingtalk.DingTalkFederatedOAuth2Provider;
import com.armorauth.federation.provider.feishu.FeishuFederatedOAuth2Provider;
import com.armorauth.federation.provider.qq.QqAccessTokenRestTemplate;
import com.armorauth.federation.provider.qq.QqFederatedOAuth2Provider;
import com.armorauth.federation.provider.qq.QqOAuth2AuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.provider.wecom.WeComAccessTokenRestTemplate;
import com.armorauth.federation.provider.wecom.WeComAuthorizationCodeGrantRequestConverter;
import com.armorauth.federation.provider.wecom.WeComFederatedOAuth2Provider;
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
                    new WechatFederatedOAuth2Provider(),
                    new DouyinFederatedOAuth2Provider(),
                    new AlipayFederatedOAuth2Provider(),
                    new DingTalkFederatedOAuth2Provider(),
                    new WeComFederatedOAuth2Provider(),
                    new FeishuFederatedOAuth2Provider()
            )
    );

    @Test
    void shouldSupportCustomTokenHandlingForGiteeQqAndWechat() {
        FederatedOAuth2Provider gitee = providerRegistry.findProvider("gitee").orElseThrow();
        FederatedOAuth2Provider qq = providerRegistry.findProvider("qq").orElseThrow();
        FederatedOAuth2Provider wechat = providerRegistry.findProvider("wechat").orElseThrow();
        FederatedOAuth2Provider douyin = providerRegistry.findProvider("douyin").orElseThrow();
        FederatedOAuth2Provider alipay = providerRegistry.findProvider("alipay").orElseThrow();
        FederatedOAuth2Provider dingtalk = providerRegistry.findProvider("dingtalk").orElseThrow();
        FederatedOAuth2Provider wecom = providerRegistry.findProvider("wecom").orElseThrow();
        FederatedOAuth2Provider feishu = providerRegistry.findProvider("feishu").orElseThrow();

        assertThat(new GiteeAccessTokenRestTemplate().supports("gitee")).isTrue();
        assertThat(new GiteeOAuth2AuthorizationCodeGrantRequestConverter().supports("gitee")).isTrue();
        assertThat(gitee.getAccessTokenRestTemplate()).isNotNull();

        assertThat(new QqAccessTokenRestTemplate().supports("qq")).isTrue();
        assertThat(new QqOAuth2AuthorizationCodeGrantRequestConverter().supports("qq")).isTrue();
        assertThat(qq.getOAuth2UserService()).isNotNull();

        assertThat(new WechatAccessTokenRestTemplate().supports("wechat")).isTrue();
        assertThat(new WechatAuthorizationCodeGrantRequestConverter().supports("wechat")).isTrue();
        assertThat(wechat.getAuthorizationRequestConverter()).isNotNull();

        assertThat(new DouyinAccessTokenRestTemplate().supports("douyin")).isTrue();
        assertThat(new DouyinAuthorizationCodeGrantRequestConverter().supports("douyin")).isTrue();
        assertThat(douyin.getAuthorizationRequestConverter()).isNotNull();
        assertThat(douyin.getOAuth2UserService()).isNotNull();

        assertThat(new AlipayAccessTokenRestTemplate().supports("alipay")).isTrue();
        assertThat(new AlipayAuthorizationCodeGrantRequestConverter().supports("alipay")).isTrue();
        assertThat(alipay.getAuthorizationRequestConverter()).isNotNull();

        assertThat(dingtalk.getAuthorizationCodeGrantRequestConverter()).isNotNull();
        assertThat(dingtalk.getAccessTokenRestTemplate()).isNotNull();
        assertThat(dingtalk.getOAuth2UserService()).isNotNull();

        assertThat(new WeComAccessTokenRestTemplate().supports("wecom")).isTrue();
        assertThat(new WeComAuthorizationCodeGrantRequestConverter().supports("wecom")).isTrue();
        assertThat(wecom.getAuthorizationRequestConverter()).isNotNull();
        assertThat(wecom.getOAuth2UserService()).isNotNull();

        assertThat(feishu.getAuthorizationCodeGrantRequestConverter()).isNotNull();
        assertThat(feishu.getAccessTokenRestTemplate()).isNotNull();
        assertThat(feishu.getOAuth2UserService()).isNotNull();
    }

    @Test
    void shouldNotTreatGithubAsCustomProvider() {
        assertThat(new GiteeAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new GiteeOAuth2AuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(new QqAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new QqOAuth2AuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(new WechatAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new WechatAuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(new DouyinAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new DouyinAuthorizationRequestConverter().supports("github")).isFalse();
        assertThat(new DouyinAuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(new AlipayAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new AlipayAuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(new WeComAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new WeComAuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(providerRegistry.findProvider("github")).isEmpty();
    }

}
