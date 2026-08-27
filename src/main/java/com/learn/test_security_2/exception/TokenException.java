package com.learn.test_security_2.exception;

public class TokenException extends RuntimeException {
    public TokenException(String message) {
        super(message);
    }

  public TokenException(String message, Throwable cause) {
    super(message, cause);
  }
}
