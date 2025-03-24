package com.springsecurity.security.service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.springsecurity.security.entity.UserEntity;
import com.springsecurity.security.repositry.UserRepo;

@Service
public class AuthServiceImpl implements AuthService{
	
	 private static final String EMAIL_REGEX = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@" +
             "(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
	
	@Autowired
	private UserRepo repo;
	
	@Autowired
	private PasswordEncoder encoder;
	
	@Override
	public ResponseEntity<Map<String, String>> signin(UserEntity user) {
		

		if(user.getEmail() == "" || user.getPassword() == "" || user.getUserName() == "" || user.getPhoneNo() == "") {
			return new ResponseEntity<Map<String,String>>(Map.of("error","Enter all fields"),HttpStatus.BAD_REQUEST);
		}
		
		boolean emailFormat = Pattern.compile(EMAIL_REGEX).matcher(user.getEmail()).matches();
		
		if(!emailFormat) {
			return new ResponseEntity<Map<String,String>>(Map.of("error","Invalid email address"),HttpStatus.BAD_REQUEST);
		}
		
		Optional<UserEntity> isExisting = repo.findByEmail(user.getEmail());
		
		if(isExisting.isPresent()) {
			return new ResponseEntity<Map<String,String>>(Map.of("error","User already exist"),HttpStatus.BAD_REQUEST);
		}
		
		Optional<UserEntity> isExistingUser = repo.findByUserName(user.getUserName());
		
		if(isExistingUser.isPresent()) {
			return new ResponseEntity<Map<String,String>>(Map.of("error","Username already exist"),HttpStatus.BAD_REQUEST);
		}
		
		if(user.getPassword().length() < 6) {
			return new ResponseEntity<Map<String,String>>(Map.of("error","Password must be more than 6 character"),HttpStatus.BAD_REQUEST);
		}
		
		user.setPassword(encoder.encode(user.getPassword()));
		
		if(user.getPhoneNo().length() != 10) {
			return new ResponseEntity<Map<String,String>>(Map.of("error","phone must 10 numbers"),HttpStatus.BAD_REQUEST);
		}
		
		repo.save(user);
		
		return new ResponseEntity<Map<String,String>>(Map.of("message","User created successfully"),HttpStatus.OK);
	}

	@Override
	public ResponseEntity<List<UserEntity>> getAllUser() {
			 List<UserEntity> user = repo.findAll();
			 return new ResponseEntity<List<UserEntity>>(user,HttpStatus.OK);
		
	}

}
