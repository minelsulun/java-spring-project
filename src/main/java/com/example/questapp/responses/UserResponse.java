package com.example.questapp.responses;

import com.example.questapp.entities.User;

import lombok.Data;

@Data
public class UserResponse {
	Long id;
	String userName;
	int avatar;
	String userInfo;

	public UserResponse(User entity) {
		this.id = entity.getId();
		this.userName = entity.getUserName();
		this.avatar = entity.getAvatar();
		this.userInfo = entity.getUserInfo();
	}
}
