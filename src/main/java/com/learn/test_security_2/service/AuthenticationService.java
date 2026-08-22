package com.learn.test_security_2.service;

import com.learn.test_security_2.dto.*;

public interface AuthenticationService {

    LoginResponse register(RegisterRequest request);

    LoginResponse login(LoginRequest request);

    RefreshTokenResponse refreshToken(RefreshTokenRequest request);

    void logout(LogoutRequest request);

}
