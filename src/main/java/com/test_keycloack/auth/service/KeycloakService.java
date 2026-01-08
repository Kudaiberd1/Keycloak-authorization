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
public class KeycloackService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final MessageSource messageSource;

    @Value("spring.application.jwt.keycloack.url")
    private String keycloackUrl;
    @Value("spring.application.jwt.keycloack.client-id")
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

    public String buildTokenEndpoint(String endpointType){
        String base = keycloackUrl;
        return base + "/protocol/openid-connect/" + endpointType;
    }
}
