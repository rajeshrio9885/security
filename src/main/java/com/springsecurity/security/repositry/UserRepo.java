package com.springsecurity.security.repositry;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.springsecurity.security.entity.UserEntity;


public interface UserRepo extends JpaRepository<UserEntity, Long>{
	
	public Optional<UserEntity> findByEmail(String email);
	public Optional<UserEntity> findByUserName(String userName);
}
