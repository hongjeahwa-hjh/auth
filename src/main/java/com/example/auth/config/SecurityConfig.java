package com.example.auth.config;


import com.example.auth.security.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Spring Security의 표준 인증 관리자
     * 사용자의 인증을 처리하는 객체
     * UserDetailsService를 이용하여 사용자 정보를 로드한다
     * PasswordEncoder도 사용한다.
     * UserDetails를 확인하여 계정상태(활성화)를 확인한다.
     * */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)  throws Exception{
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http){
        http
                .cors(AbstractHttpConfigurer::disable)      // cors check disable
                .csrf(AbstractHttpConfigurer::disable)      // csrf check disable
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests( auth ->
                        auth
                                .requestMatchers("/health", "/signup","/login","/refresh","/loginex").permitAll()      // 여기에 적힌 route를 통과시킴
                                .anyRequest().authenticated()   // 그 외는 다 인증 필요
                )
                .exceptionHandling(ex ->

                        ex
                                // 인증 실패시 401에러를 클라이언트에게 보냄
                                .authenticationEntryPoint((request, response, authException) -> {
                                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);    // 401
                                    response.setContentType("application/json;charset=UTF-8");
                                    response.getWriter().write("{\"error\" : \"Unauthorized\", \"message\": \"인증이 필요합니다\"}");
                                })
                                // 권한 없음, 403에러를 클라이언트에게 보냄
                                .accessDeniedHandler((request, response, accessDeniedException) -> {
                                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);    // 403
                                    response.setContentType("application/json;charset=UTF-8");
                                    response.getWriter().write("{\"error\" : \"Access Denied\", \"message\": \"권한이 없습니다\"}");
                                })
                )
                // UsernamePasswordAuthenticationFilter 보다 앞에 jwtAuthenticationFilter 넣어라
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
