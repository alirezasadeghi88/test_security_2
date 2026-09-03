package com.learn.test_security_2.service;

import com.learn.test_security_2.model.RefreshToken;
import com.learn.test_security_2.model.User;

public interface RefreshTokenService {

    RefreshToken createRefreshToken(User user);

    RefreshToken verifyToken(String token);

    void revokeToken(String token);

    void revokeAll(User user);

}
