package com.heaptrace.net;

import java.util.Arrays;
import java.util.List;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.heaptrace.net.entity.User;
import com.heaptrace.net.repository.UserRepository;

@SpringBootApplication
public class SpringSecurityWithSpringBootJwtPocExampleApplication {
 
	@Autowired
	private UserRepository userRepository;
	
	@PostConstruct
	public void initUser() {
		
		List<User> user = Arrays.asList(new User(101,"User1","User1"),new User(102,"User2","User2"));
		
		userRepository.saveAll(user);
	}
	
	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityWithSpringBootJwtPocExampleApplication.class, args);
	}

}
