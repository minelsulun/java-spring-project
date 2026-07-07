package com.example.questapp.controllers;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.questapp.entities.User;
import com.example.questapp.responses.UserResponse;
import com.example.questapp.services.UserService;

@RestController
@RequestMapping("/users")
public class UserController {

	private UserService userService;

	public UserController(UserService userService) {
		this.userService=userService;
	}

	@GetMapping
	public List<UserResponse> getAllUsers(){
		return userService.gelAllUsers().stream().map(UserResponse::new).toList();
	}

	@PostMapping
	public UserResponse createUser(@RequestBody User newUser) {
		return new UserResponse(userService.saveOneUser(newUser));
	}

	@GetMapping("/{userId}")
	public ResponseEntity<UserResponse> getOneUser(@PathVariable Long userId) {
		User user = userService.getOneUserById(userId);
		if (user == null)
			return ResponseEntity.notFound().build();
		return ResponseEntity.ok(new UserResponse(user));
	}
	@PutMapping("/{userId}")
	public ResponseEntity<UserResponse> updateOneUser(@PathVariable Long userId, @RequestBody User newUser) {
		User user = userService.updateOneUser(userId,newUser);
		if (user == null)
			return ResponseEntity.notFound().build();
		return ResponseEntity.ok(new UserResponse(user));
	}
	@DeleteMapping("/{userId}")
	public void deleteOneUser(@PathVariable Long userId) {
		userService.deleteById(userId);

	}
}
