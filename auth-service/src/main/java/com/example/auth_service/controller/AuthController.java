package com.example.auth_service.controller;

import com.example.auth_service.model.LoginRequest;
import com.example.auth_service.model.LoginResponse;
import com.example.auth_service.model.User;
import com.example.auth_service.service.UserService;
import com.example.auth_service.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        Optional<User> opt = userService.findByEmail(loginRequest.getEmail());
        if (opt.isPresent()) {
            User user = opt.get();
            if (user.getPassword().equals(loginRequest.getPassword())) {
                userService.recordLogin(user);
                String token = jwtUtil.generateToken(user);
                return ResponseEntity.ok(new LoginResponse(token));
            }
        }
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body("Invalid credentials");
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        try {
            if (userService.findByEmail(user.getEmail()).isPresent()) {
                return ResponseEntity
                        .status(HttpStatus.CONFLICT)
                        .body("Email already registered.");
            }

            userService.save(user);
            return ResponseEntity.ok("User registered successfully.");
        } catch (Exception e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Registration failed.");
        }
    }

    // 🔒 Protected route (accessible by all authenticated users)
    @GetMapping("/secure")
    public ResponseEntity<String> secureEndpoint(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            String email = jwtUtil.extractEmail(token);
            return ResponseEntity.ok("🔐 Hello, " + email + "! You accessed a protected route.");
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No token provided.");
    }

    // 🔐 Admin-only endpoint
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<String> adminOnlyEndpoint() {
        return ResponseEntity.ok("✅ You are an ADMIN!");
    }
}
