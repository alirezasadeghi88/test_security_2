package com.learn.test_security_2.exception;

public class ApiException extends RuntimeException {
    public ApiException(String message) {
        super(message);
    }
}
