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

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

public enum ExtendedOAuth2ClientProvider {

    GITEE {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("user_info");
            builder.authorizationUri("https://gitee.com/oauth/authorize");
            builder.tokenUri("https://gitee.com/oauth/token");
            builder.userInfoUri("https://gitee.com/api/v5/user");
            builder.userNameAttributeName("id");
            builder.clientName("gitee");
            return builder;
        }
    },
    QQ {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("get_user_info");
            builder.authorizationUri("https://graph.qq.com/oauth2.0/authorize");
            builder.tokenUri("https://graph.qq.com/oauth2.0/token");
            builder.userInfoUri("https://graph.qq.com/user/get_user_info");
            builder.userNameAttributeName("openid");
            builder.clientName("qq");
            return builder;
        }
    },
    WECHAT {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.NONE,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("snsapi_login");
            builder.authorizationUri("https://open.weixin.qq.com/connect/qrconnect");
            builder.tokenUri("https://api.weixin.qq.com/sns/oauth2/access_token");
            builder.userInfoUri("https://api.weixin.qq.com/sns/userinfo");
            builder.userNameAttributeName("openid");
            builder.clientName("wechat");
            return builder;
        }
    },
    MICROSOFT {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("openid", "profile", "email", "User.Read");
            builder.authorizationUri("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
            builder.tokenUri("https://login.microsoftonline.com/common/oauth2/v2.0/token");
            builder.jwkSetUri("https://login.microsoftonline.com/common/discovery/v2.0/keys");
            builder.userInfoUri("https://graph.microsoft.com/oidc/userinfo");
            builder.userNameAttributeName("sub");
            builder.clientName("Microsoft");
            return builder;
        }
    },
    GITLAB {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("read_user");
            builder.authorizationUri("https://gitlab.com/oauth/authorize");
            builder.tokenUri("https://gitlab.com/oauth/token");
            builder.userInfoUri("https://gitlab.com/api/v4/user");
            builder.userNameAttributeName("id");
            builder.clientName("GitLab");
            return builder;
        }
    },
    DISCORD {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("identify", "email");
            builder.authorizationUri("https://discord.com/oauth2/authorize");
            builder.tokenUri("https://discord.com/api/oauth2/token");
            builder.userInfoUri("https://discord.com/api/users/@me");
            builder.userNameAttributeName("id");
            builder.clientName("Discord");
            return builder;
        }
    },
    SLACK {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("openid", "profile", "email");
            builder.authorizationUri("https://slack.com/openid/connect/authorize");
            builder.tokenUri("https://slack.com/api/openid.connect.token");
            builder.jwkSetUri("https://slack.com/openid/connect/keys");
            builder.userInfoUri("https://slack.com/api/openid.connect.userInfo");
            builder.userNameAttributeName("sub");
            builder.clientName("Slack");
            return builder;
        }
    },
    LINKEDIN {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("openid", "profile", "email");
            builder.authorizationUri("https://www.linkedin.com/oauth/v2/authorization");
            builder.tokenUri("https://www.linkedin.com/oauth/v2/accessToken");
            builder.userInfoUri("https://api.linkedin.com/v2/userinfo");
            builder.userNameAttributeName("sub");
            builder.clientName("LinkedIn");
            return builder;
        }
    },
    APPLE {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("openid", "name", "email");
            builder.authorizationUri("https://appleid.apple.com/auth/authorize");
            builder.tokenUri("https://appleid.apple.com/auth/token");
            builder.jwkSetUri("https://appleid.apple.com/auth/keys");
            builder.userNameAttributeName("sub");
            builder.clientName("Apple");
            return builder;
        }
    },
    WEIBO {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("all");
            builder.authorizationUri("https://api.weibo.com/oauth2/authorize");
            builder.tokenUri("https://api.weibo.com/oauth2/access_token");
            builder.userInfoUri("https://api.weibo.com/2/users/show.json");
            builder.userNameAttributeName("idstr");
            builder.clientName("Weibo");
            return builder;
        }
    },
    BAIDU {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("basic");
            builder.authorizationUri("https://openapi.baidu.com/oauth/2.0/authorize");
            builder.tokenUri("https://openapi.baidu.com/oauth/2.0/token");
            builder.userInfoUri("https://openapi.baidu.com/rest/2.0/passport/users/getInfo");
            builder.userNameAttributeName("userid");
            builder.clientName("Baidu");
            return builder;
        }
    },
    OSCHINA {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("user");
            builder.authorizationUri("https://www.oschina.net/action/oauth2/authorize");
            builder.tokenUri("https://www.oschina.net/action/openapi/token");
            builder.userInfoUri("https://www.oschina.net/action/openapi/user");
            builder.userNameAttributeName("id");
            builder.clientName("OSChina");
            return builder;
        }
    },
    DOUYIN {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("user_info");
            builder.authorizationUri("https://open.douyin.com/platform/oauth/connect");
            builder.tokenUri("https://open.douyin.com/oauth/access_token/");
            builder.userInfoUri("https://open.douyin.com/oauth/userinfo/");
            builder.userNameAttributeName("open_id");
            builder.clientName("Douyin");
            return builder;
        }
    },
    ALIPAY {
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId,
                    ClientAuthenticationMethod.NONE,
                    DEFAULT_REDIRECT_URL
            );
            builder.scope("auth_user");
            builder.authorizationUri("https://openauth.alipay.com/oauth2/publicAppAuthorize.htm");
            builder.tokenUri("https://openapi.alipay.com/gateway.do");
            builder.userInfoUri("https://openapi.alipay.com/gateway.do");
            builder.userNameAttributeName("user_id");
            builder.clientName("Alipay");
            return builder;
        }
    };

    private static final String DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}";

    protected final ClientRegistration.Builder getBuilder(
            String registrationId,
            ClientAuthenticationMethod method,
            String redirectUri) {
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
        builder.clientAuthenticationMethod(method);
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        builder.redirectUri(redirectUri);
        return builder;
    }

    public static boolean matchNameLowerCase(ExtendedOAuth2ClientProvider provider, String registrationId) {
        return StringUtils.equals(provider.name().toLowerCase(), registrationId.toLowerCase());
    }

    public static String getNameLowerCase(ExtendedOAuth2ClientProvider provider) {
        return provider.name().toLowerCase();
    }

    public abstract ClientRegistration.Builder getBuilder(String registrationId);

}
