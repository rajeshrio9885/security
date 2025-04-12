package com.springsecurity.security.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
public class UserEntity {
	
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	@Column(unique = true,nullable = false)
	private String email;
	@Column(name="password",length = 255,nullable = false)
	@JsonIgnore
	private String password;
	@Column(unique = true,nullable = false)
	private String userName;
	@Column(unique = true,nullable = false)
	private String PhoneNo;
	
}
