package com.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Removing Bearer Prefix
        }
        return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails) {
        String userName = userDetails.getUsername();
        return Jwts.builder()
                .subject(userName)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key())
                    .build().parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT Token: {}" +e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT Token is Expired: {}" +e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT Token is Unsupported: {}" +e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims String is Empty: {}" +e.getMessage());
        }
        return false;
    }
}
