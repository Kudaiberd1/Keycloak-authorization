package com.test_keycloack.auth.controller;

import com.test_keycloack.auth.dto.request.UserAuthRequest;
import com.test_keycloack.auth.dto.response.AuthResponse;
import com.test_keycloack.auth.service.KeycloakService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final KeycloakService keycloakService;

    @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid UserAuthRequest userAuthRequest) throws BadRequestException {
        log.info("Login attempt for user: {}", userAuthRequest.username());
        AuthResponse authResponse = keycloakService.getAuthResponse(userAuthRequest.username(), userAuthRequest.password());
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping(value = "/logout")
    public ResponseEntity<Void> logout(@RequestBody Map<String, String> body) throws BadRequestException {
        log.info("Logout attempt");
        keycloakService.logout(body.get("refreshToken"));
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping(value = "/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody Map<String, String> body) throws BadRequestException {
        log.info("Refresh attempt");
        String refreshToken = body.get("refreshToken");
        return ResponseEntity.ok(keycloakService.refreshToken(refreshToken));
    }
}
