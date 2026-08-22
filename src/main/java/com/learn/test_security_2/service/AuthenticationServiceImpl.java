package com.learn.test_security_2.service;

import com.learn.test_security_2.dto.*;
import com.learn.test_security_2.model.RefreshToken;
import com.learn.test_security_2.model.Role;
import com.learn.test_security_2.model.User;
import com.learn.test_security_2.repository.RoleRepository;
import com.learn.test_security_2.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Override
    @Transactional
    public LoginResponse register(RegisterRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists.");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists.");
        }

        Role customerRole = roleRepository.findByCode("ROLE_CUSTOMER")
                .orElseThrow(() ->
                        new RuntimeException("Default role not found."));


        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.getRoles().add(customerRole);
        user.setEnabled(true);
        user.setAccountNonLocked(true);
        user.setAccountNonExpired(true);
        user.setCredentialsNonExpired(true);
        user = userRepository.save(user);

        UserDetails userDetails =
                org.springframework.security.core.userdetails.User
                        .withUsername(user.getUsername())
                        .password(user.getPassword())
                        .authorities(
                                user.getRoles()
                                        .stream()
                                        .map(Role::getCode)
                                        .toArray(String[]::new)
                        )
                        .build();

        String accessToken = jwtService.generateToken(userDetails);

        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(user);

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .expiresIn(900000L)
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles())
                .message("User registered successfully.")
                .build();

    }

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {


        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() ->
                        new RuntimeException("User not found."));

        user.setLastLogin(LocalDateTime.now());

        userRepository.save(user);

        // Build UserDetails
        UserDetails userDetails =
                org.springframework.security.core.userdetails.User
                        .withUsername(user.getUsername())
                        .password(user.getPassword())
                        .authorities(
                                user.getRoles()
                                        .stream()
                                        .map(Role::getCode)
                                        .toArray(String[]::new)
                        )
                        .accountExpired(!user.getAccountNonExpired())
                        .accountLocked(!user.getAccountNonLocked())
                        .credentialsExpired(!user.getCredentialsNonExpired())
                        .disabled(!user.getEnabled())
                        .build();

        String accessToken = jwtService.generateToken(userDetails);
        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(user);
        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(900000L)
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles())
                .message("Login successfully.")
                .build();

    }

    @Override
    @Transactional
    public RefreshTokenResponse refreshToken(RefreshTokenRequest request) {

        RefreshToken refreshToken =
                refreshTokenService.verifyToken(request.getRefreshToken());

        User user = refreshToken.getUser();

        UserDetails userDetails =
                org.springframework.security.core.userdetails.User
                        .withUsername(user.getUsername())
                        .password(user.getPassword())
                        .authorities(
                                user.getRoles()
                                        .stream()
                                        .map(Role::getCode)
                                        .toArray(String[]::new)
                        )
                        .accountExpired(!user.getAccountNonExpired())
                        .accountLocked(!user.getAccountNonLocked())
                        .credentialsExpired(!user.getCredentialsNonExpired())
                        .disabled(!user.getEnabled())
                        .build();

        String accessToken = jwtService.generateToken(userDetails);

        return RefreshTokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpiration())
                .build();

    }

    @Override
    @Transactional
    public void logout(LogoutRequest request) {

        if (request == null ||
                request.getRefreshToken() == null ||
                request.getRefreshToken().isBlank()) {

            throw new RuntimeException("Refresh Token is required.");

        }

        RefreshToken refreshToken =
                refreshTokenService.verifyToken(request.getRefreshToken());

        refreshTokenService.revokeToken(refreshToken.getToken());

        SecurityContextHolder.clearContext();

    }
}
