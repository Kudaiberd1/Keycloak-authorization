package com.test_keycloack.auth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

    @GetMapping
    public String hello() {
        return "Hello World";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('client_admin')")

    public String admin() {
        return "Hello Admin";
    }
}
