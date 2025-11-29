package com.example.auth.controller;


import com.example.auth.dto.*;
import com.example.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok("Authentication Service is running");
    }


    /*
    * {
    *   "email": "test@gmail.com"
    *   "password": "123456"
    *   "username": "홍길동"
    * }
    * */



    /**
     * 회원 가입 요청을 처리하는 엔드포인트
     * <p>
     * 클라이언트로부터 전달받은 {@link RequestSignup} 데이터를 기반으로 새로운 사용자를 등록합니다.
     * 요청 데이터는 {@link Valid} 어노테이션을 사용하여 검증됩니다.
     * 회원 가입 성공 여부에 따라 HTTP 상태 코드와 {@link ApiResponse}를 반환합니다.
     * </p>
     *
     * @param requestSignup 클라이언트에서 전달받은 회원 가입 정보 (이메일, 비밀번호, 사용자 이름 등)
     * @return {@link ResponseEntity} 객체로 반환되며, 본문에는 {@link ApiResponse}가 포함됩니다.
     *         <ul>
     *             <li>성공 시: HTTP 201 (CREATED), ApiResponse.success 메시지</li>
     *             <li>실패 시: HTTP 400 (BAD_REQUEST), ApiResponse.error 메시지</li>
     *         </ul>
     */
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody RequestSignup requestSignup) {
        ApiResponse<Void> response = authService.signup(requestSignup);
        HttpStatus statusCode = response.getSuccess() ? HttpStatus.CREATED : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(statusCode).body(response);
    }

    /**
     * 로그인 요청을 처리하는 엔드포인트입니다.
     * <p>
     * 클라이언트로부터 전달받은 {@link RequestLogin} 정보를 기반으로 사용자 인증을 수행합니다.
     * 요청 데이터는 {@link Valid} 어노테이션을 사용하여 유효성 검증이 수행됩니다.
     * 로그인 성공 시 Access Token과 Refresh Token 등의 정보가 포함된 {@link ApiResponse}가 반환됩니다.
     * </p>
     *
     * @param requestLogin 클라이언트에서 전달받은 로그인 정보 (이메일, 비밀번호 등)
     * @return {@link ResponseEntity} 객체로 반환되며, 본문에는 {@link ApiResponse}가 포함됩니다.
     *         <ul>
     *             <li>성공 시: HTTP 201 (CREATED), 인증 토큰과 성공 메시지 포함</li>
     *             <li>실패 시: HTTP 400 (BAD_REQUEST), 오류 메시지 포함</li>
     *         </ul>
     */
    @PostMapping("/login")
    public ResponseEntity<?> login (@Valid @RequestBody RequestLogin requestLogin){
        ApiResponse<?> response = authService.login(requestLogin);
        HttpStatusCode statusCode = response.getSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(statusCode).body(response);
    }

    public String extractRefreshTokenFromBody (TokenRefreshRequest body){
        if(body == null || body.getRefreshToken() == null || body.getRefreshToken().isBlank())
            return null;

        return body.getRefreshToken();
    }


    @PostMapping("/refresh")
    @SuppressWarnings("NullableProblems")
    public ResponseEntity<ApiResponse<TokenRefreshResponse>> refresh(
            HttpServletRequest request,         // web 용
            @RequestBody(required = false) @Valid TokenRefreshRequest body  // mobile
    ){
        String refreshToken = extractRefreshTokenFromBody( body );
        TokenRefreshResponse tokenRefreshResponse = authService.refreshAccessToken(refreshToken);

        return ResponseEntity.ok(
                ApiResponse.success("Access Token 재발급 성공", tokenRefreshResponse)
        );

    }




}
