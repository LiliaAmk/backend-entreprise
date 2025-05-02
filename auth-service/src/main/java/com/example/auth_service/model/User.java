package com.example.auth_service.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity @Table(name="users")
@Data @NoArgsConstructor @AllArgsConstructor
public class User {
  @Id @GeneratedValue(strategy=GenerationType.IDENTITY)
  private Long id;

  @Column(nullable=false, unique=true)
  private String email;

  @Column(nullable=false)
  private String password;

  @Column(nullable=false)
  private String salt;

  private LocalDateTime lastLogin;
  private LocalDateTime lastLogout;
  private int loginCount;

  /** Comma‑separated roles, e.g. "ROLE_USER,ROLE_ADMIN" */
  @Column(nullable=false)
  private String roles;
}
