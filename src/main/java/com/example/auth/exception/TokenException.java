package com.example.auth.exception;

/**
 * 토큰 관련 Exception class
 * Refresh Token이 유효하지 않거나 만료된 경우에 발생되는 Exception
 * */

public class TokenException extends RuntimeException {
    public TokenException(String message) {
        super(message);
    }

    public TokenException(String message, Throwable cause){
        super(message, cause);
    }
}
