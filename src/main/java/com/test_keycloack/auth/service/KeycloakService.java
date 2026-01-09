package com.test_keycloack.auth.service;

import com.test_keycloack.auth.dto.response.AuthResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;

import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeycloakService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final MessageSource messageSource;

    @Value("${spring.application.jwt.keycloak.url}")
    private String keycloakUrl;
    @Value("${spring.application.jwt.keycloak.client-id}")
    private String clientId;

    public AuthResponse getAuthResponse(String username, String password) throws BadRequestException {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new BadRequestException(messageSource.getMessage("error.auth.usernameOrPasswordEmpty", null, LocaleContextHolder.getLocale()));
        }

        String tokenUrl = buildTokenEndpoint("token");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("username", username);
        form.add("password", password);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        log.info(tokenUrl);
        log.info(response.toString());

        if(response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            String accessToken = response.getBody().get("access_token").toString();
            String refreshToken = response.getBody().get("refresh_token").toString();
            Long expiresIn = Long.valueOf(response.getBody().get("expires_in").toString());
            String tokenType = response.getBody().get("token_type").toString();

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .expiresIn(expiresIn)
                    .tokenType(tokenType)
                    .build();
        } else {
            throw new RuntimeException(messageSource.getMessage("error.auth.failedToGetAuthResponse",
                    new Object[]{response.getStatusCode()}, LocaleContextHolder.getLocale()));
        }
    }

    public void logout(String refreshToken) {
        String tokenUrl = buildTokenEndpoint("logout");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
        if(response.getStatusCode().is2xxSuccessful()) {
            log.info("User logged out successfully");
        }else{
            log.error("Failed to logout user: {}", response.getStatusCode());
            throw new RuntimeException(messageSource.getMessage("error.auth.failedToLogout",
                    new Object[]{response.getStatusCode()}, LocaleContextHolder.getLocale()));
        }
    }

    public String buildTokenEndpoint(String endpointType){
        String base = keycloakUrl;
        return base + "/protocol/openid-connect/" + endpointType;
    }
}
