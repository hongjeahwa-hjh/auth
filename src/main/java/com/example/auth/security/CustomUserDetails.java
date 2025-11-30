package com.example.auth.security;

import com.example.auth.entity.User;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * Spring Security에서 다루는 UserDetails의 구현체
 * 우리가 개발한 User Entity를 Spring Security가 이해할 수 있도록 구현
 * */
@Getter
@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {
    private final User user;

    /**
     * 사용자의 권한 목록을 반환
     * Spring Security가 Authorization할때 이 메소드를 호출한다.
     *
     * @return 권한 목록(예: ROLE_USER, ROLE_ADMIN)
     * */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(user.getRole().name()));
    }

    /**
     * User에 저장된 암호화된 패스워드를 반환한다.
     *
     * @return 암호화된 비밀번호
     * */
    @Override
    public @Nullable String getPassword() {
        return user.getPassword();
    }

    /**
     * User에 저장된 사용자아이디를 반환한다.
     *
     * @return 사용자 이메일
     * */
    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.getIsActive();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.getIsActive();
    }
}
