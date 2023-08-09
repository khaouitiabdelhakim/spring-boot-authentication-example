package com.abdelhakim.spring.login.repository;

import java.util.Optional;

import com.abdelhakim.spring.login.models.RefreshToken;
import com.abdelhakim.spring.login.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;


@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    int deleteByUser(User user);
}
