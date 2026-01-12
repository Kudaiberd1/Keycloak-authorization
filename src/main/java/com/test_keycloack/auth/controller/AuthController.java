package com.test_keycloack.auth.controller;

import com.test_keycloack.auth.dto.request.UserAuthRequest;
import com.test_keycloack.auth.dto.response.AuthResponse;
import com.test_keycloack.auth.dto.response.UserDetailsResponse;
import com.test_keycloack.auth.service.KeycloakService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final KeycloakService keycloakService;

    @GetMapping(value = "/me")
    public ResponseEntity<UserDetailsResponse> me(@AuthenticationPrincipal Jwt jwt) {
        UserDetailsResponse userDetails = keycloakService.getUserDetails(jwt);
        return ResponseEntity.ok(userDetails);
    }

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid UserAuthRequest userAuthRequest) throws BadRequestException {
        AuthResponse authResponse = keycloakService.getAuthResponse(userAuthRequest.username(), userAuthRequest.password());
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping(value = "/logout")
    public ResponseEntity<Void> logout(@RequestBody Map<String, String> body) throws BadRequestException {
        keycloakService.logout(body.get("refreshToken"));
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping(value = "/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody Map<String, String> body) throws BadRequestException {
        String refreshToken = body.get("refreshToken");
        return ResponseEntity.ok(keycloakService.refreshToken(refreshToken));
    }
}
