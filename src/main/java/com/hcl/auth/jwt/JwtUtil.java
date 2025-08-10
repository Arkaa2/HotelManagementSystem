package com.hcl.auth.jwt;

import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.hcl.entity.User;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
	@Value("${jwt.secret}")
	private String secret;
	@Value("${jwt.expire}")
	private long expire;

	private Key getSiginingKey() {
		return Keys.hmacShaKeyFor(secret.getBytes());
	}

	public String GenerateKey(User user) {
		return Jwts.builder().setSubject(user.getEmail()).claim("role", user.getRole()).setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + expire)).signWith(getSiginingKey(),SignatureAlgorithm.HS256).compact();

	}
	public boolean isExpireToken(String token) {
		Date date = Jwts.parserBuilder().setSigningKey(getSiginingKey()).build().parseClaimsJws(token).getBody()
				.getExpiration();
		return date.before(new Date());
	}
	
	public String ExtractToken(String token) {
		return Jwts.parserBuilder().setSigningKey(getSiginingKey()).build().parseClaimsJws(token).getBody().getSubject();
	}

	public boolean ValidateKey(String token, User user) {
		String email = ExtractEmail(token);
		return user.getEmail().equals(email) && !isExpireToken(token);
	}
	public String ExtractEmail(String token) {
		return Jwts.parserBuilder().setSigningKey(getSiginingKey()).build().parseClaimsJws(token).getBody().getSubject();
	}
	

}
