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

import com.armorauth.data.repository.UserInfoRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FederatedAccountServiceTest {

    @Test
    void shouldFallbackAndAppendSuffixWhenUsernameConflicts() {
        UserInfoRepository userInfoRepository = mock(UserInfoRepository.class);
        when(userInfoRepository.existsByUsername("gitee_abc12345")).thenReturn(true);
        when(userInfoRepository.existsByUsername("gitee_abc123451")).thenReturn(false);
        FederatedAccountService service = new FederatedAccountService(
                userInfoRepository,
                PasswordEncoderFactories.createDelegatingPasswordEncoder()
        );

        String username = service.generateAvailableUsername("gitee", "abc12345xxxx", "");

        assertThat(username).isEqualTo("gitee_abc123451");
    }

    @Test
    void shouldNormalizeDisplayNameIntoUsername() {
        UserInfoRepository userInfoRepository = mock(UserInfoRepository.class);
        when(userInfoRepository.existsByUsername(anyString())).thenReturn(false);
        FederatedAccountService service = new FederatedAccountService(
                userInfoRepository,
                PasswordEncoderFactories.createDelegatingPasswordEncoder()
        );

        String username = service.generateAvailableUsername("gitee", "abc12345xxxx", "  Alice / Builder  ");

        assertThat(username).isEqualTo("Alice_Builder");
    }
}
