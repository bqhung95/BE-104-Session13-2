package com.example.identityservice.controller;

import com.example.identityservice.dto.RegisterRequest;
import com.example.identityservice.dto.UserResponse;
import com.example.identityservice.entity.User;
import com.example.identityservice.service.AuthService;
import com.example.identityservice.util.JwtUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * API test: trả về JWT cho một user đã tồn tại trong DB
     * GET /api/auth/test-token?username=nguyenvana
     */
    @GetMapping("/test-token")
    public ResponseEntity<Map<String, Object>> testToken(@RequestParam String username) {
        User user = authService.findByUsername(username);
        String token = jwtUtil.generateToken(user);

        return ResponseEntity.ok(Map.of(
                "username", user.getUsername(),
                "role", user.getRole(),
                "tokenType", "Bearer",
                "expiresIn", 3600,
                "accessToken", token
        ));
    }
}
