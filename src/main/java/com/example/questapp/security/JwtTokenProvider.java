
package com.example.questapp.security;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.example.questapp.services.UserDetailsServiceImpl;

import ch.qos.logback.classic.Logger;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {
	

    @Value("${questapp.app.secret}")
    private String APP_SECRET;
    
    @Value("${questapp.expires.in}")
    private long EXPIRES_IN;
    
    private final UserDetailsServiceImpl userDetailsServiceImpl;

    public JwtTokenProvider(UserDetailsServiceImpl userDetailsServiceImpl) {
        this.userDetailsServiceImpl = userDetailsServiceImpl;
    }
    
    // Token oluşturur
    public String generateJwtToken(Authentication auth) {
        JwtUserDetails userDetails = (JwtUserDetails) auth.getPrincipal();
        Date expireDate = new Date(new Date().getTime() + EXPIRES_IN);

        // APP_SECRET'i bir Key nesnesine dönüştür
        Key key = getSigningKey();

        return Jwts.builder()
                .setSubject(Long.toString(userDetails.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expireDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
    
    public String generateJwtTokenByUserId(Long userId) {
        Date expireDate = new Date(new Date().getTime() + EXPIRES_IN);

        // APP_SECRET'i bir Key nesnesine dönüştür
        Key key = getSigningKey();

        return Jwts.builder()
                .setSubject(Long.toString(userId))
                .setIssuedAt(new Date())
                .setExpiration(expireDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
    
    // Token'dan kullanıcı ID'sini alır
    public Long getUserIdFromJwt(String token) {
        Key key = getSigningKey();

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }
    
    public boolean validateToken(String token) {
        try {
            Key key = getSigningKey();

            // Token'ı çözümle ve doğrula
            Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);

            // Token süresi kontrolü
            return !isTokenExpired(token);
        } catch (MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            Logger logger = (Logger) LoggerFactory.getLogger(JwtTokenProvider.class);
            logger.error("Token validation failed: " + e.getMessage());
            return false;
        }
    }

    // Token'ın süresinin dolup dolmadığını kontrol eder
    private boolean isTokenExpired(String token) {
        try {
            Key key = getSigningKey();

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch (Exception e) {
            return true;
        }
    }
   

    // APP_SECRET'i Key nesnesine dönüştüren yardımcı metod
    private Key getSigningKey() {
        byte[] secretKeyBytes = Base64.getDecoder().decode(APP_SECRET);
        return Keys.hmacShaKeyFor(secretKeyBytes);
    }
    
    public Authentication getAuthentication(String token) {
        Long userId = getUserIdFromJwt(token);
        if (userId == null) {
            throw new RuntimeException("Invalid user ID from JWT");
        }

        UserDetails userDetails = userDetailsServiceImpl.loadUserById(userId);
        if (userDetails == null) {
            throw new RuntimeException("User details not found for ID: " + userId);
        }

        Logger logger = (Logger) LoggerFactory.getLogger(JwtTokenProvider.class);
        logger.info("User authenticated: " + userDetails.getUsername());

        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }
}

