package com.example.auth_service.model;

import lombok.Data;

@Data
public class LoginRequest {
    // must match what your controller expects
    private String email;
    private String password;
}
