package com.example.auth.security;

import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Spring Security의 UserDetailsService 인터페이스의 구현체
 * Spring Security가 사용자 인증(Authentication)시 이 서비스(@Service)를 통해 정보를 전달한다
 * username을 받아서 UserDetails(CustomUserDetails)객체를 반환하는 역할을 수행한다.
 * */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    /**
     * Spring Security(에서의 AuthenticationManager)가 인증 처리를 할때 자동으로 호출하는 메소드
     *
     * @param username 사용자 고유 식별자(우리 시스템의 경우에는 사용자 email)
     * @return UserDetails(우리 시스템의 경우에는 CustomUserDetails)객체를 반환한다
     * @throws UsernameNotFoundException 사용자를 찾을 수 없는 경우에 발생시킴
     * */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(()->{
                   return new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username);
                });
        // CustomUserDetails 인스턴스를 User 인스턴스를 이용하여 생성하고 이를 반환하도록 한다
        return new CustomUserDetails(user);
    }
}
