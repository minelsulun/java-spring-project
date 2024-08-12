package com.example.questapp.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.questapp.services.UserDetailsServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
	
	@Autowired
	JwtTokenProvider jwtTokenProvider;
	
	@Autowired
	UserDetailsServiceImpl userDetailsService;
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
	        throws ServletException, IOException {
	    try {
	        String token = getJwtFromRequest(request);
	        if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
	            Long userId = jwtTokenProvider.getUserIdFromJwt(token);
	            UserDetails userDetails = userDetailsService.loadUserById(userId);
	            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
	            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
	            SecurityContextHolder.getContext().setAuthentication(authentication);
	        }
	    } catch (Exception ex) {
	        logger.error("Could not set user authentication in security context", ex);
	    }

	    filterChain.doFilter(request, response);
	}

	private String getJwtFromRequest(HttpServletRequest request) {
	    String bearerToken = request.getHeader("Authorization");
	    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
	        return bearerToken.substring(7);
	    }
	    return null;
	}

}
