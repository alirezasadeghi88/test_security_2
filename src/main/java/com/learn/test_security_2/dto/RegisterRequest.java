package com.learn.test_security_2.dto;

import lombok.Data;

@Data
public class RegisterRequest {

    private String firstName;

    private String lastName;

    private String username;

    private String email;

    private String password;

}
