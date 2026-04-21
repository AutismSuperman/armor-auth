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
package com.armorauth.federation;

import org.springframework.util.StringUtils;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;

public record PendingFederatedContext(
        String registrationId,
        String providerUserId,
        String providerUsername,
        String displayName,
        String avatarUrl,
        String providerAttributes,
        String suggestedUsername,
        long createdAt
) implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    public boolean isComplete() {
        return StringUtils.hasText(this.registrationId)
                && StringUtils.hasText(this.providerUserId)
                && StringUtils.hasText(this.suggestedUsername);
    }

    public boolean isExpired(Duration ttl) {
        return System.currentTimeMillis() - this.createdAt > ttl.toMillis();
    }

    public FederatedUserProfile toProfile() {
        return new FederatedUserProfile(
                this.registrationId,
                this.providerUserId,
                this.providerUsername,
                this.displayName,
                this.avatarUrl,
                this.providerAttributes
        );
    }
}
