package com.example.questapp.entities;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Table;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import lombok.Data;

import org.hibernate.annotations.OnDelete;
import org.hibernate.annotations.OnDeleteAction;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;


@Entity
@Table(name="comment")
@Data
public class Comment {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)

	Long id;
    
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="post_id",nullable=false)
	@OnDelete(action=OnDeleteAction.CASCADE)
	@JsonIgnore
	Post post;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="user_id",nullable=false)
	@OnDelete(action=OnDeleteAction.CASCADE)
	@JsonIgnore
	User user;
	
	@Lob
	@Column(columnDefinition="text")
	String text;
}
