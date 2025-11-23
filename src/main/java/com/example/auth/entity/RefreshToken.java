package com.example.auth.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "token", nullable = false, length = 500)
    private String token;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "is_revoked", nullable = false)
    @Builder.Default
    private boolean revoked = false;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    // FK: user_id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_refresh_token_user"))
    private User user;

    // refresh token이 갖어야할 비지니스 로직
    /**
     * refresh token이 만료되었는지 확인
     * @return 만료되었으면 true, 아니면 false를 반환
     * */
    public boolean isExpired() {
        // expiresAt <-- 이 시간보다 이후이면 true 반환
        return LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * 토큰이 유효한지 확인하는 메소드
     * @return 취소되지 않았고, 만료되지 않았으면 true를 반환
     * */
    public boolean isValid() {
        return !revoked && !isExpired();
    }

    /**
     * 토큰을 폐기처분시킴
     * */
    public void revoke() {
        this.revoked = true;
    }

    /**
     * 토큰이 사용할 시간을 업데이트를 한다.
     * */
    public void updateLastUsedAt() {
        this.lastUsedAt = LocalDateTime.now();
    }
}

