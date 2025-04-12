package com.springsecurity.security.config;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtil {

	private final static String SECRET_KEY = "6WUPVk4RYvqFLbRRVdr4Ex8v7dvmymQ6";
	
	private final SecretKey secretKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
	
	public String generateToken(UserDetails userDetails) {
		return Jwts.builder()
				.issuedAt(new Date())
				.expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
				.signWith(secretKey,Jwts.SIG.HS256)
				.subject(userDetails.getUsername())
				.compact();
	}
	
	public boolean vaildateToken(String token,UserDetails userDetails) {
		return extractUserName(token).equals(userDetails.getUsername());
	}
	
	public String extractUserName(String token) {
		return Jwts.parser().verifyWith(secretKey)
		.build().parseSignedClaims(token).getPayload().getSubject();
	}
	
	
	public String getTokenFromCookie(HttpServletRequest request) {
		if(request.getCookies() != null) {
			for(Cookie cookie : request.getCookies() ) {
				if(cookie.getName().equals("token")) {
					return "Bearer "+cookie.getValue();
				}
			}
		}
		return null;

	}
}
