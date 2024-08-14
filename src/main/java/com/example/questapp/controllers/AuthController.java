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
import com.example.questapp.responses.AuthResponse;
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
    public AuthResponse login(@RequestBody UserRequest loginRequest) {
		logger.debug("Login attempt with username: {}", loginRequest.getUserName());

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                loginRequest.getUserName(), loginRequest.getPassword());
        Authentication auth = authenticationManager.authenticate(authToken);
        SecurityContextHolder.getContext().setAuthentication(auth);

        String jwtToken = jwtTokenProvider.generateJwtToken(auth);
        logger.info("Login successful for username: {}", loginRequest.getUserName());
        User user= userService.getOneUserByName(loginRequest.getUserName());
        AuthResponse authResponse = new AuthResponse();
        
        authResponse.setMassage("Bearer"+jwtToken);
        authResponse.setUserId(user.getId());
        return authResponse ;    
	 	 
    }
	
	@PostMapping("/register")
	 public ResponseEntity<AuthResponse> register(@RequestBody UserRequest registerRequest){
        AuthResponse authResponse = new AuthResponse();
		 if(userService.getOneUserByName(registerRequest.getUserName()) != null) {
			 authResponse.setMassage("Username already in use");
	         return new ResponseEntity<>(authResponse, HttpStatus.BAD_REQUEST);
		 }
	     User user = new User();
	     user.setUserName(registerRequest.getUserName());
	     user.setPassword(passwordEncoder.encode(registerRequest.getPassword())); // Şifre burada şifrelenecek
	     userService.saveOneUser(user);
		 authResponse.setMassage("User successfully registered");
	     return new ResponseEntity<>(authResponse, HttpStatus.CREATED);	    
	 }
	
	
	 
		
}
