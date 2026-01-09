package com.test_keycloack.auth.service;

import com.test_keycloack.auth.dto.response.AuthResponse;
import com.test_keycloack.auth.dto.response.KeycloakTokenResponse;
import com.test_keycloack.auth.exceptions.UnauthorizedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;

import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeycloakService {

    @Value("${spring.application.jwt.keycloak.url}")
    private String keycloakUrl;
    @Value("${spring.application.jwt.keycloak.client-id}")
    private String clientId;
    @Value("${spring.application.jwt.keycloak.client-secret}")
    private String clientSecret;

    public AuthResponse getAuthResponse(String username, String password) throws BadRequestException {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new BadRequestException("Username or password is null or blank");
        }

        String tokenUrl = buildTokenEndpoint("token");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<KeycloakTokenResponse> response = restTemplate.postForEntity(tokenUrl, request, KeycloakTokenResponse.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {

                return mapTokenResponse(response.getBody());
            } else {
                throw new RuntimeException("Failed to get AuthResponse");
            }
        }catch (HttpClientErrorException.Unauthorized e) {
            log.warn("Authentication failed for user '{}': Invalid credentials", username);
            throw new UnauthorizedException("Invalid credentials");
        } catch (HttpClientErrorException e) {
            log.error("HTTP error from Keycloak: {} - {}", e.getStatusCode(), e.getMessage());
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new UnauthorizedException("Invalid credentials");
            }
            throw new UnauthorizedException("Invalid credentials");
        } catch (Exception e) {
            log.error("Unexpected error during authentication: ", e);
            throw new UnauthorizedException("Invalid credentials");
        }
    }

    public void logout(String refreshToken) throws BadRequestException {
        String tokenUrl = buildTokenEndpoint("logout");
        if(refreshToken == null || refreshToken.isBlank()) {
            throw new BadRequestException("Refresh token is empty");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("User logged out successfully");
            } else {
                log.error("Failed to logout user: {}", response.getStatusCode());
                throw new RuntimeException("Logout failed");
            }
        }catch (Exception e) {
            log.error("Error during logout: ", e);
            throw new RuntimeException("Logout failed");
        }
    }

    public AuthResponse refreshToken(String refreshToken) throws BadRequestException {
        String tokenUrl = buildTokenEndpoint("token");
        if(refreshToken == null || refreshToken.isBlank()) {
            throw new BadRequestException("Refresh token is empty");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("refresh_token", refreshToken);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<KeycloakTokenResponse> response = restTemplate.postForEntity(tokenUrl, request, KeycloakTokenResponse.class);

            if (response.getStatusCode().is2xxSuccessful()) {

                if (response.getBody() != null) {
                    return mapTokenResponse(response.getBody());
                } else {
                    throw new RuntimeException("Unexpected Refresh Response!");
                }
            }
            throw new RuntimeException("Unexpected Refresh Response!");
        }catch (HttpClientErrorException e){
            String msg = e.getResponseBodyAsString();
            log.warn("Token refresh failed with status {}: {}", e.getStatusCode(), msg);
            if (e.getStatusCode() == HttpStatus.BAD_REQUEST) {
                throw new UnauthorizedException("Invalid grant!");
            }
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new UnauthorizedException("Invalid ClientId!");
            }
            throw new UnauthorizedException("Refresh failed!");
        }catch (Exception e) {
            log.error("Unexpected error during token refresh", e);
            throw new UnauthorizedException("Refresh failed!");
        }
    }

    public String buildTokenEndpoint(String endpointType){
        String base = keycloakUrl;
        return base + "/protocol/openid-connect/" + endpointType;
    }

    public AuthResponse mapTokenResponse(KeycloakTokenResponse tokenResponse) {
        return AuthResponse.builder()
                .accessToken(tokenResponse.getAccessToken())
                .refreshToken(tokenResponse.getRefreshToken())
                .expiresIn(tokenResponse.getExpiresIn())
                .tokenType(tokenResponse.getTokenType())
                .build();
    }
}
