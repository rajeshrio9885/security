package com.springsecurity.security.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.springsecurity.security.config.JwtUtil;
import com.springsecurity.security.dto.Login;
import com.springsecurity.security.entity.UserEntity;
import com.springsecurity.security.service.AuthService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/user")
public class AuthController {
	
	@Autowired
	private AuthService authService;
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@PostMapping("/signin")
	public ResponseEntity<Map<String, String>> signin(@RequestBody UserEntity user){
		ResponseEntity<Map<String, String>> userSignin = authService.signin(user);
		return userSignin;
		
	}
	
	@GetMapping("/getUser")
	public ResponseEntity<List<UserEntity>> getAllUser(){
		return authService.getAllUser();
	}
	
	@PostMapping("/login")
	public ResponseEntity<Map<String, String>> login(@RequestBody Login user,HttpServletResponse response,HttpServletRequest request){
		
		if(user.getUserName() == "" || user.getPassword() == "") {
			return new ResponseEntity<Map<String,String>>(Map.of("error","Enter all the fileds"),HttpStatus.BAD_REQUEST);
		}
		
		try {
			Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword()));
			UserDetails userDetails = (UserDetails) auth.getPrincipal();
			String token = jwtUtil.generateToken(userDetails);
			Cookie cookie = new Cookie("token", token);
			
			cookie.setMaxAge(7*24*60*60);
			cookie.setHttpOnly(true);
			cookie.setPath("/");
			cookie.setSecure(true);
			response.addCookie(cookie);
			
			return new ResponseEntity<Map<String,String>>(Map.of("message","login successfully"),HttpStatus.OK);
		}catch(Exception e) {
			return new ResponseEntity<Map<String,String>>(Map.of("error","invalid user"),HttpStatus.UNAUTHORIZED);
		}
		

	
	}
}
