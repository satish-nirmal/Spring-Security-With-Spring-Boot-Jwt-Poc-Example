package com.heaptrace.net.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.heaptrace.net.entity.AuthRequest;
import com.heaptrace.net.util.JwtUtil;

@RestController
public class UserController {

	@Autowired
	private JwtUtil jwtUtil;

	@Autowired
	private AuthenticationManager authenticationManager;

	@GetMapping("/msg")
	public String msg() {
		return "Good evening! Greetings from User Controller";
	}

	@PostMapping("/authenticate")
	public String generateToken(@RequestBody AuthRequest authRequest) throws Exception {

		try {

			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

		} catch (Exception e) {

			throw new Exception("Invalid username or password, Please enter valid credentials");

		}

		return jwtUtil.generateToken(authRequest.getUsername());

	}
}
