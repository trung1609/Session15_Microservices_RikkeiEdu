package com.example.identityservice.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class FormRegister {
    private String username;
    private String password;
    private String role;
}
