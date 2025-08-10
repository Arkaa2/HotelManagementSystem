package com.hcl.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hcl.auth.dto.AuthRequest;
import com.hcl.auth.dto.AuthResponse;
import com.hcl.auth.dto.RegisterRequest;
import com.hcl.auth.service.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {
	@Autowired
	private AuthService authService;

	@PostMapping("/register")
	public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest req) {
		AuthResponse res = authService.register(req);
		return new ResponseEntity<AuthResponse>(res, HttpStatusCode.valueOf(202));
	}

	@PostMapping("login")
	public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest req) {
		AuthResponse res = authService.login(req);
		return ResponseEntity.status(HttpStatusCode.valueOf(200)).body(res);
	}

}
