package com.springsecurity.security.service;

import java.util.Collections;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.springsecurity.security.entity.UserEntity;
import com.springsecurity.security.repositry.UserRepo;

@Component
public class CustomUserDetailsService implements UserDetailsService {
	
	@Autowired
	private UserRepo repo;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserEntity user = repo.findByUserName(username).orElseThrow(()-> new UsernameNotFoundException("User not found"));
		return new User(user.getUserName(), user.getPassword(), Collections.singleton(new SimpleGrantedAuthority("USER_ROLE")));
	}

}
