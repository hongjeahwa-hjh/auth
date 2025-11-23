package com.example.auth.controller;

import com.example.auth.dto.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<String>> me() {
        return ResponseEntity.ok(ApiResponse.success("안녕하세요"));
    }

}
