package com.santechture.api.service;

import com.santechture.api.dto.GeneralResponse;
import com.santechture.api.dto.admin.AdminDto;
import com.santechture.api.entity.Admin;
import com.santechture.api.exception.BusinessExceptions;
import com.santechture.api.repository.AdminRepository;
import com.santechture.api.validation.LoginRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import com.santechture.api.security.config.JwtService;
import com.santechture.api.security.responses.AuthenticationResponse;

import java.util.Objects;
import java.util.Optional;

@Service

public class AdminService {


    private final AdminRepository adminRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;


    @Autowired
    public AdminService(AdminRepository adminRepository, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.adminRepository = adminRepository;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public ResponseEntity<GeneralResponse> login(LoginRequest request) throws BusinessExceptions {


            Optional<Admin> userToCheckEmailValidity = Optional.ofNullable(adminRepository.findByUsernameIgnoreCase(request.getUsername()));
            if(Objects.isNull(userToCheckEmailValidity) || !userToCheckEmailValidity.get().getPassword().equals(request.getPassword())){
                throw new BusinessExceptions("login.credentials.not.match");
            }else {
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.getUsername(),
                                request.getPassword()
                        )
                );
                var admin = adminRepository.findByUsernameIgnoreCase(request.getUsername());
                var jwtToken= jwtService.generateToken(admin);
                AuthenticationResponse authenticationResponse=AuthenticationResponse.builder()
                        .token(jwtToken)
                        .admin(admin)
                        .build();

                return new GeneralResponse().response(authenticationResponse);
            }

//        Admin admin = adminRepository.findByUsernameIgnoreCase(request.getUsername());
//

//
//        return new GeneralResponse().response(new AdminDto(admin));
    }
}
