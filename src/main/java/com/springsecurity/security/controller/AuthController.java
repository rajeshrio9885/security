package com.springsecurity.security.controller;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.management.RuntimeErrorException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.springsecurity.security.config.JwtUtil;
import com.springsecurity.security.dto.Login;
import com.springsecurity.security.entity.UserEntity;
import com.springsecurity.security.repositry.UserRepo;
import com.springsecurity.security.service.AuthService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@CrossOrigin(origins = "http://localhost:5173")
@RestController
@RequestMapping("/api/user")
public class AuthController {
	
	@Autowired
	private AuthService authService;
	
	@Autowired
	private UserRepo repo;
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@PostMapping("/signin")
	public ResponseEntity<Map<String, String>> signin(@RequestBody UserEntity user){
		
		try {
			ResponseEntity<Map<String, String>> userSignin = authService.signin(user);
			return userSignin;
		} catch (Exception e) {
			// TODO: handle exception
			return new ResponseEntity<Map<String,String>>(Map.of("error",e.getMessage()),HttpStatus.BAD_REQUEST);
		}
		
		
	}
	
	@GetMapping("/getUser")
	public ResponseEntity<List<UserEntity>> getAllUser(){
		return authService.getAllUser();
	}
	
	@GetMapping("/me")
	public ResponseEntity<UserEntity> getUser(HttpServletRequest request){
			String token = jwtUtil.getTokenFromCookie(request).substring(7);
			if(token != null) {
				String userName = jwtUtil.extractUserName(token);
				UserEntity user = repo.findByUserName(userName).orElseThrow(()-> new UsernameNotFoundException("user not found"));
				return new ResponseEntity<UserEntity>(user,HttpStatus.OK);
			}
			throw new RuntimeException("Not authenticated");		
	}
	
	@PostMapping("/login")
	public ResponseEntity<Map<String, String>> login(@RequestBody Login user,HttpServletResponse response){
		
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
