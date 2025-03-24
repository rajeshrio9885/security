package com.springsecurity.security.service;

import java.util.List;
import java.util.Map;

import org.springframework.http.ResponseEntity;

import com.springsecurity.security.entity.UserEntity;

public interface AuthService {
	public ResponseEntity<Map<String, String>> signin(UserEntity user);
	public ResponseEntity<List<UserEntity>> getAllUser();
}
