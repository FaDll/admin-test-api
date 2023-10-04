package com.santechture.api.service;

import com.santechture.api.dto.GeneralResponse;
import com.santechture.api.dto.admin.AdminDto;
import com.santechture.api.dto.user.UserDto;
import com.santechture.api.entity.Admin;
import com.santechture.api.entity.User;
import com.santechture.api.exception.BusinessExceptions;
import com.santechture.api.repository.UserRepository;
import com.santechture.api.security.config.JwtService;
import com.santechture.api.validation.AddUserRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class UserService {


    private final UserRepository userRepository;
    private final JwtService jwtService;



    public UserService(UserRepository userRepository,JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }


    public ResponseEntity<GeneralResponse> list(Pageable pageable){
        return new GeneralResponse().response(userRepository.findAll(pageable));
    }

    public ResponseEntity<GeneralResponse> addNewUser(AddUserRequest request,String token) throws BusinessExceptions {

        if(userRepository.existsByUsernameIgnoreCase(request.getUsername())){
            throw new BusinessExceptions("username.exist");
        } else if (userRepository.existsByEmailIgnoreCase(request.getEmail())) {
            throw new BusinessExceptions("email.exist");
        }

        User user = new User(request.getUsername(),request.getEmail());
        userRepository.save(user);
        String tokenWithNoBearer = jwtService.extractJwtToken(token);

        Integer adminId = jwtService.extractAdminId(tokenWithNoBearer);
        String username = jwtService.extractUsername(tokenWithNoBearer);

        Admin admin = Admin.builder()
                .adminId(adminId)
                .username(username)
                .build();





        return new GeneralResponse().response(new AdminDto(admin));
    }

}
