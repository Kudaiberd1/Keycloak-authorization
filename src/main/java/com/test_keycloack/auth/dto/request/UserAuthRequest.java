package com.test_keycloack.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UserAuthRequest(
        @NotBlank()
        @Size(max = 255)
        String username,

        @NotBlank(message = "{validation.auth.password.required}")
        @Size(max = 255, message = "{validation.auth.password.size}")
        String password
) {
}
