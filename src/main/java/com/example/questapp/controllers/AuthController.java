package com.example.questapp.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.questapp.entities.User;
import com.example.questapp.requests.UserRequest;
import com.example.questapp.security.JwtTokenProvider;
import com.example.questapp.services.UserService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/auth")
public class AuthController {
	
	private AuthenticationManager authenticationManager;
	
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

	
	private JwtTokenProvider jwtTokenProvider;
	
	private UserService userService;
	
	private PasswordEncoder passwordEncoder;
	
	public AuthController(AuthenticationManager authenticationManager, UserService userService,PasswordEncoder passwordEncoder,JwtTokenProvider jwtTokenProvider) {
		this.authenticationManager=authenticationManager;
		this.userService= userService;
		this.passwordEncoder=passwordEncoder;
		this.jwtTokenProvider=jwtTokenProvider;
	}
	
	 @PostMapping("/login")
	    public ResponseEntity<String> login(@RequestBody UserRequest loginRequest) {
	        logger.debug("Login attempt with username: {}", loginRequest.getUserName());

	        try {
	            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
	                    loginRequest.getUserName(), loginRequest.getPassword());
	            Authentication auth = authenticationManager.authenticate(authToken);
	            SecurityContextHolder.getContext().setAuthentication(auth);

	            String jwtToken = jwtTokenProvider.generateJwtToken(auth);
	            logger.info("Login successful for username: {}", loginRequest.getUserName());

	            return ResponseEntity.ok("Bearer " + jwtToken);
	        } catch (Exception e) {
	            logger.error("Login failed for username: {}. Error: {}", loginRequest.getUserName(), e.getMessage());
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.toString());
	        }
	    }
	
	 @PostMapping("/register")
	 public ResponseEntity<String> register(@RequestBody UserRequest registerRequest){
	     if(userService.getOneUserByName(registerRequest.getUserName()) != null)
	         return new ResponseEntity<>("Username already in use", HttpStatus.BAD_REQUEST);
	     
	     User user = new User();
	     user.setUserName(registerRequest.getUserName());
	     user.setPassword(passwordEncoder.encode(registerRequest.getPassword())); // Şifre burada şifrelenecek
	     userService.saveOneUser(user);
	     return new ResponseEntity<>("User successfully registered", HttpStatus.CREATED);
	 }
		
}
