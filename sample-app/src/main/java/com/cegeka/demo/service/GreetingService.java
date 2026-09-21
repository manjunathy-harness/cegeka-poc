package com.cegeka.demo.service;

import org.apache.commons.text.StringSubstitutor;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class GreetingService {

    public String greet(String name) {
        String template =
                "Hello ${name}! Welcome to the Cegeka Spring Boot application.";

        return StringSubstitutor.replace(
                template,
                Map.of("name", name)
        );
    }
}
