package com.learn.test_security_2.service;

import com.learn.test_security_2.exception.TokenException;
import com.learn.test_security_2.model.RefreshToken;
import com.learn.test_security_2.model.User;
import com.learn.test_security_2.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository repository;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Override
    public RefreshToken createRefreshToken(User user) {

        repository.deleteByUser(user);

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUser(user);

        refreshToken.setToken(UUID.randomUUID().toString());

        refreshToken.setExpiryDate(
                LocalDateTime.now()
                        .plusSeconds(refreshTokenExpiration / 1000)
        );

        refreshToken.setExpired(false);

        refreshToken.setRevoked(false);

        return repository.save(refreshToken);

    }

    @Override
    public RefreshToken verifyToken(String token) {

        RefreshToken refreshToken = repository.findByToken(token)
                .orElseThrow(() ->
                        new TokenException("Refresh token not found"));

        if (refreshToken.getRevoked()) {

            throw new TokenException("Refresh token revoked");

        }

        if (refreshToken.getExpired()) {

            throw new TokenException("Refresh token expired");

        }

        if (refreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {

            refreshToken.setExpired(true);

            repository.save(refreshToken);

            throw new TokenException("Refresh token expired");

        }

        return refreshToken;

    }

    @Override
    public void revokeToken(String token) {

        RefreshToken refreshToken = repository.findByToken(token)
                .orElseThrow(() ->
                        new TokenException("Refresh token not found"));

        refreshToken.setRevoked(true);

        refreshToken.setRevokedAt(LocalDateTime.now());

        repository.save(refreshToken);

    }

    @Override
    public void revokeAll(User user) {

        repository.deleteByUser(user);

    }

}
