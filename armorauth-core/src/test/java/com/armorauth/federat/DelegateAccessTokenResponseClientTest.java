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
package com.armorauth.federat;

import com.armorauth.federat.gitee.GiteeAccessTokenRestTemplate;
import com.armorauth.federat.gitee.GiteeOAuth2AuthorizationCodeGrantRequestConverter;
import com.armorauth.federat.qq.QqAccessTokenRestTemplate;
import com.armorauth.federat.qq.QqOAuth2AuthorizationCodeGrantRequestConverter;
import com.armorauth.federat.wechat.WechatAccessTokenRestTemplate;
import com.armorauth.federat.wechat.WechatAuthorizationCodeGrantRequestConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DelegateAccessTokenResponseClientTest {

    @Test
    void shouldSupportCustomTokenHandlingForGiteeQqAndWechat() {
        assertThat(new GiteeAccessTokenRestTemplate().supports("gitee")).isTrue();
        assertThat(new GiteeOAuth2AuthorizationCodeGrantRequestConverter().supports("gitee")).isTrue();

        assertThat(new QqAccessTokenRestTemplate().supports("qq")).isTrue();
        assertThat(new QqOAuth2AuthorizationCodeGrantRequestConverter().supports("qq")).isTrue();

        assertThat(new WechatAccessTokenRestTemplate().supports("wechat")).isTrue();
        assertThat(new WechatAuthorizationCodeGrantRequestConverter().supports("wechat")).isTrue();
    }

    @Test
    void shouldNotTreatGithubAsCustomProvider() {
        assertThat(new GiteeAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new GiteeOAuth2AuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(new QqAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new QqOAuth2AuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
        assertThat(new WechatAccessTokenRestTemplate().supports("github")).isFalse();
        assertThat(new WechatAuthorizationCodeGrantRequestConverter().supports("github")).isFalse();
    }

}
