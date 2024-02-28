package com.hannmx.WebSecurity;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DataController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/private-data")
    public String privateData() {
        return "This is private data";
    }

    @GetMapping("/public-data")
    public String publicData() {
        return "This is public data";
    }
}

