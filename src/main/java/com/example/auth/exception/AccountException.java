package com.example.auth.exception;

/**
 * 사용자 계정 상태 관련 Exception
 * 계정이 비활성화되있거나 이메일(아이디) 대조등이 실패한 경우에 발생시킴
 * */

public class AccountException extends RuntimeException {
    public AccountException(String message) {
        super(message);
    }

    public AccountException(String message, Throwable cause){
        super(message, cause);
    }
}
