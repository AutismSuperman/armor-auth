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

public record FederatedUserProfile(
        String registrationId,
        String providerUserId,
        String providerUsername,
        String displayName,
        String avatarUrl,
        String providerAttributes
) {

    public PendingFederatedContext toPendingContext(String suggestedUsername) {
        return new PendingFederatedContext(
                this.registrationId,
                this.providerUserId,
                this.providerUsername,
                this.displayName,
                this.avatarUrl,
                this.providerAttributes,
                suggestedUsername,
                System.currentTimeMillis()
        );
    }
}
