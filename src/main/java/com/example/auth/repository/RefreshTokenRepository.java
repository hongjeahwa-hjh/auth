package com.example.auth.repository;

import com.example.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
@SuppressWarnings("NullableProblems")
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
}
