package com.example.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApiResponse<T> {
    private Boolean success;
    private String message;
    private T data;

    // 데이터가 없는 성공 응답
    public static <T> ApiResponse<T> success(String message){
        return new ApiResponse<>(true, message, null);
    }

    // 데이터가 있는 성공 응답
    public static <T> ApiResponse<T> success(String message, T data){
        return new ApiResponse<>(true, message, data);
    }

    // 에러 응답
    public static <T> ApiResponse<T> error(String message){
        return new ApiResponse<>(false, message, null);


    }
}
