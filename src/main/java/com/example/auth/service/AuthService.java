package com.example.auth.service;

import com.example.auth.dto.*;
import com.example.auth.entity.RefreshToken;
import com.example.auth.entity.User;
import com.example.auth.exception.AccountException;
import com.example.auth.exception.TokenException;
import com.example.auth.repository.RefreshTokenRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;        // token발급기이자 검증기

    /**
     * 회원 가입 요청을 처리하는 서비스 메서드입니다.
     * <p>
     * 클라이언트로부터 전달받은 {@link RequestSignup} 정보를 기반으로 새로운 {@link User} 엔티티를 생성하고 데이터베이스에 저장합니다.
     * 이메일은 소문자로 정규화되며, 비밀번호는 {@link org.springframework.security.crypto.password.PasswordEncoder}를 사용해 암호화됩니다.
     * </p>
     *
     * @param requestSignup 회원 가입 정보가 담긴 {@link RequestSignup} 객체 (이메일, 비밀번호, 사용자 이름 등)
     * @return {@link ApiResponse} 객체
     *         <ul>
     *             <li>회원 가입 성공 시: 성공 메시지 포함</li>
     *             <li>이미 가입된 이메일일 경우: 오류 메시지 "이미 가입된 회원입니다" 반환</li>
     *             <li>기타 예외 발생 시: 오류 메시지 "회원가입 중 오류가 발생했습니다" 반환</li>
     *         </ul>
     */
    @Transactional
    public ApiResponse<Void> signup(RequestSignup requestSignup) {
        // 이메일 정규화(Normalize)
        String email = requestSignup.getEmail().trim().toLowerCase();

        log.info("request email : {}", email);

        try {
            // requestSignup정보를 기반으로 User Entity 인스턴스를 생성
            User user = User.builder()
                    .email(email)
                    .password(passwordEncoder.encode(requestSignup.getPassword()))
                    .nickName(requestSignup.getUsername())
                    .role(User.Role.ROLE_USER)
                    .isActive(true)
                    .build();

            userRepository.save(user);
            return ApiResponse.success("회원 가입 성공");
        } catch (DataIntegrityViolationException e){
            return ApiResponse.error("이미 가입된 회원입니다");
        } catch (Exception e){
            log.error("회원 가입중 오류 발생: {}", e.getMessage());
            return ApiResponse.error("회원가입 중 오류가 발생했습니다");
        }
    }

    /**
     * 로그인 요청을 처리하는 서비스 메서드입니다.
     * <p>
     * 클라이언트로부터 전달받은 {@link RequestLogin} 정보를 기반으로 사용자를 인증하고,
     * 인증이 성공하면 Access Token과 Refresh Token을 생성하여 반환합니다.
     * Refresh Token은 {@link RefreshToken} 엔티티로 데이터베이스에 저장됩니다.
     * </p>
     *
     * <p>처리 과정:</p>
     * <ol>
     *     <li>이메일 정규화 및 사용자 조회</li>
     *     <li>비밀번호 검증</li>
     *     <li>계정 활성 상태 확인</li>
     *     <li>Access Token 및 Refresh Token 생성</li>
     *     <li>Refresh Token 데이터베이스 저장</li>
     *     <li>로그인 응답 생성 및 반환</li>
     * </ol>
     *
     * @param requestLogin 로그인 정보가 담긴 {@link RequestLogin} 객체 (이메일, 비밀번호)
     * @return {@link ApiResponse} 객체
     *         <ul>
     *             <li>로그인 성공 시: 성공 메시지와 {@link LoginResponse} 포함</li>
     *             <li>이메일이 존재하지 않거나 비밀번호 불일치, 비활성 계정인 경우: 오류 메시지 반환</li>
     *         </ul>
     */
    @Transactional
    public ApiResponse<?> login(RequestLogin requestLogin){
        String normalizeEmail = requestLogin.getEmail().trim().toLowerCase();
        // 이메일로 사용자 조회
        Optional<User> optUser = userRepository.findByEmail(normalizeEmail);
        User user = null;
        if(optUser.isPresent())
            user = optUser.get();
        if (user == null){
            // 존재하지 않는 이메일이면 에러변환 후 종료
            return createErrorResponse("존재하지 않는 사용자 이메일입니다");
        }
        // 비밀번호 체크하기
        boolean isValid = passwordEncoder.matches(
                requestLogin.getPassword(), user.getPassword()
        );
        if( !isValid ) {
            return createErrorResponse("비밀번호가 일치하지 않습니다");
        }

        // 계정 상태 확인하기
        if(!user.getIsActive()) {
            return createErrorResponse("현재 비활성화된 계정입니다");
        }

        // 토큰을 생성
        String accessToken = jwtTokenProvider.generateAccessToken(user.getEmail(), user.getId());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getEmail());

        // refresh token은 데이터베이스에 저장한다
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .token(refreshToken)
                .user(user)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.ofInstant(
                        jwtTokenProvider.getRefreshTokenExpiryDate().toInstant(),
                        ZoneId.systemDefault()
                )).build();

        refreshTokenRepository.save(refreshTokenEntity);

        LoginResponse loginResponse = LoginResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getNickName())
                .role(user.getRole().toString())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();

        return ApiResponse.success("로그인 성공", loginResponse);

    }

    private ApiResponse<Void> createErrorResponse(String message){
        return ApiResponse.error(message);
    }

    public TokenRefreshResponse refreshAccessToken(String refreshToken) {
        // 1. refresh token 검증하기
        if( !jwtTokenProvider.validateToken(refreshToken) ){
            throw new TokenException("유효하지 않은 RefreshToken입니다.");
        }

        // 2. Refresh Token으로부터 이메일 추출하기
        String email = jwtTokenProvider.getEmailFromToken(refreshToken);

        // 3. DB에 해당 사용자가 존재하는지, 해당 refresh token이 존재하는지 확인
        RefreshToken tokenEntity = refreshTokenRepository.findByToken(refreshToken).orElseThrow(() -> {
                    return new TokenException("유효하지 않은 Refresh Token입니다.");
        });

        // 4. refresh token이 만료되었는지 확인
        if(tokenEntity.getExpiresAt().isBefore((LocalDateTime.now()))){
            throw new TokenException("Refresh Token이 만료되었습니다.");
        }

        // 5. 사용자 조회
        User user = tokenEntity.getUser();
        if (user == null || !user.getIsActive()){
            throw new AccountException("비활성화된 사용자입니다.");
        }

        // 6. email 아이디 체크하기
        if(!user.getEmail().equals(email)){
            throw new AccountException("잘못된 사용자입니다.");
        }

        // 통과!
        String newAccessToken = jwtTokenProvider.generateAccessToken(user.getEmail(), user.getId());
        // 토큰 응답 객체를 생성
        TokenRefreshResponse response = new TokenRefreshResponse();
        // 새로 발급받은 Access Token
        response.setAccessToken(newAccessToken);
        // Access Token 발급을 위해 사용된 Refresh Token
        response.setRefreshToken(refreshToken);

        return response;

    }
}
