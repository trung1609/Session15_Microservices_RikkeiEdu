package com.example.identityservice.dto;

import lombok.*;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class FormRegister {
    private String username;
    private String password;
    private String role;
    private List<String> permissions;
}
