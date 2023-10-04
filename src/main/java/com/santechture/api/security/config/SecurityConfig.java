package com.santechture.api.security.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
//@EnableMethodSecurity
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .cors(AbstractHttpConfigurer::disable)

                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                                .antMatchers("/admin").permitAll()
                                .anyRequest()
                                .authenticated()
//                        .antMatchers("/user/**").hasRole(Role.ADMIN.name())
//                        .requestMatchers(GET,"/api/admin/**").hasAnyAuthority(ADMIN_READ.name())
//                        .requestMatchers(PUT,"/api/admin/**").hasAnyAuthority(ADMIN_UPDATE.name())
//                        .requestMatchers(POST,"/api/admin/**").hasAnyAuthority(ADMIN_CREATE.name())
//                        .requestMatchers(DELETE,"/api/admin/**").hasAnyAuthority(ADMIN_DELETE.name())

                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }
}
