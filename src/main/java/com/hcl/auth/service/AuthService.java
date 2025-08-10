package com.hcl.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.hcl.auth.dto.AuthRequest;
import com.hcl.auth.dto.AuthResponse;
import com.hcl.auth.dto.RegisterRequest;
import com.hcl.auth.jwt.JwtUtil;
import com.hcl.entity.User;
import com.hcl.repository.UserRepository;

@Service
public class AuthService {
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private PasswordEncoder passwordEncoder;

	public AuthResponse register(RegisterRequest req) {
		User user = User.builder().username(req.getUsername()).email(req.getEmail())
				.password(passwordEncoder.encode(req.getPassword())).role(req.getRole()).build();
		user = userRepository.save(user);
		String token = jwtUtil.GenerateKey(user);
		return AuthResponse.builder().token(token).username(user.getUsername()).role(user.getRole()).build();
	}

	public AuthResponse login(AuthRequest req) {

		User user = userRepository.findByEmail(req.getEmail())
				.orElseThrow(() -> new RuntimeException("User not found"));
		if (!passwordEncoder.matches(req.getPassword(), user.getPassword())) {
			throw new RuntimeException("Credentials not matched");
		}
		String token = jwtUtil.GenerateKey(user);
		return AuthResponse.builder().token(token).username(user.getUsername()).role(user.getRole()).build();

	}
}
