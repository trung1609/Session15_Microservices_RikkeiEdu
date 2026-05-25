package com.example.identityservice.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FormLogin {
    private String username;
    private String password;
}
