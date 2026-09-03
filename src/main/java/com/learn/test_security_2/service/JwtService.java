package com.learn.test_security_2.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.access-token-expiration}")
    private Long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration}")
    private Long refreshTokenExpiration;

    private SecretKey signingKey;

    @PostConstruct
    public void init() {

        byte[] keyBytes = Decoders.BASE64.decode(secret);

        signingKey = Keys.hmacShaKeyFor(keyBytes);

    }


    public String generateToken(UserDetails userDetails) {

        Map<String, Object> claims = new HashMap<>();

        claims.put(
                "roles",
                userDetails.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList())
        );

        return generateToken(claims, userDetails);

    }


    public String generateToken(Map<String, Object> claims,
                                UserDetails userDetails) {

        return Jwts.builder()

                .claims(claims)

                .subject(userDetails.getUsername())

                .issuer(issuer)

                .issuedAt(new Date())

                .expiration(
                        new Date(
                                System.currentTimeMillis()
                                        + accessTokenExpiration
                        )
                )

                .signWith(signingKey)

                .compact();

    }


    public boolean isTokenValid(String token,
                                UserDetails userDetails) {

        String username = extractUsername(token);

        return username.equals(userDetails.getUsername())
                && !isTokenExpired(token);

    }


    public String extractUsername(String token) {

        return extractClaim(
                token,
                Claims::getSubject
        );

    }


    public Date extractExpiration(String token) {

        return extractClaim(
                token,
                Claims::getExpiration
        );

    }


    public <T> T extractClaim(
            String token,
            Function<Claims, T> resolver
    ) {

        Claims claims = extractAllClaims(token);

        return resolver.apply(claims);

    }


    private Claims extractAllClaims(String token) {

        return Jwts.parser()

                .verifyWith(signingKey)

                .build()

                .parseSignedClaims(token)

                .getPayload();

    }


    private boolean isTokenExpired(String token) {

        return extractExpiration(token)

                .before(new Date());

    }


    public Long getAccessTokenExpiration() {

        return accessTokenExpiration;

    }


    public Long getRefreshTokenExpiration() {

        return refreshTokenExpiration;

    }

}
