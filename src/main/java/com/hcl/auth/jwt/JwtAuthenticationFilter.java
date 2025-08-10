package com.hcl.auth.jwt;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.hcl.entity.User;
import com.hcl.repository.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private JwtUtil jwtUtil;

	@Override
	public void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain)
			throws IOException, ServletException {
		final String authHead = req.getHeader("Authorization");
		String jwtToken = null, email = null;
		if (authHead != null && authHead.startsWith("Bearer ")) {
			jwtToken = authHead.substring(7);
			email = jwtUtil.ExtractEmail(jwtToken);

		}
		if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			User user = userRepository.findByEmail(email).orElse(null);
			if (user != null && jwtUtil.ValidateKey(jwtToken, user)) {
				String role = user.getRole();
				List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user, null,
						authorities);
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		filterChain.doFilter(req, res);
	}

}
