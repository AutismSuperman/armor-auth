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

import org.springframework.util.StringUtils;

public enum FederatedLoginMode {

    AUTO("auto"),
    CONFIRM("confirm");

    private final String parameterValue;

    FederatedLoginMode(String parameterValue) {
        this.parameterValue = parameterValue;
    }

    public String getParameterValue() {
        return parameterValue;
    }

    public static FederatedLoginMode resolveForAuthorization(String mode) {
        if (!StringUtils.hasText(mode)) {
            return AUTO;
        }
        for (FederatedLoginMode candidate : values()) {
            if (candidate.parameterValue.equalsIgnoreCase(mode)) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("无效的联合登录模式，只允许 auto 或 confirm。");
    }

    public static FederatedLoginMode resolveForPage(String mode) {
        if (!StringUtils.hasText(mode)) {
            return AUTO;
        }
        for (FederatedLoginMode candidate : values()) {
            if (candidate.parameterValue.equalsIgnoreCase(mode)) {
                return candidate;
            }
        }
        return AUTO;
    }
}
