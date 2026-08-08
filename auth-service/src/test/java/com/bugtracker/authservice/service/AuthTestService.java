package com.bugtracker.authservice.service;

import com.bugtracker.authservice.dto.AuthResponse;
import com.bugtracker.authservice.dto.LoginRequest;
import com.bugtracker.authservice.dto.RegisterRequest;
import com.bugtracker.authservice.entity.User;
import com.bugtracker.authservice.enums.Role;
import com.bugtracker.authservice.exception.InvalidCredentialsException;
import com.bugtracker.authservice.exception.UserAlreadyExistsException;
import com.bugtracker.authservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    private User user;

    @BeforeEach
    void setUp() {

        user = User.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.DEVELOPER)
                .build();
    }

    @Test
    void register_shouldCreateUserSuccessfully() {

        RegisterRequest request = new RegisterRequest();
        request.setUsername("testuser");
        request.setEmail("test@example.com");
        request.setPassword("Password123");

        when(userRepository.existsByEmail(request.getEmail()))
                .thenReturn(false);

        when(userRepository.existsByUsername(request.getUsername()))
                .thenReturn(false);

        when(passwordEncoder.encode(request.getPassword()))
                .thenReturn("encodedPassword");

        when(userRepository.save(any(User.class)))
                .thenReturn(user);

        AuthResponse response = authService.register(request);

        assertNotNull(response);
        assertEquals("testuser", response.getUsername());
        assertEquals("test@example.com", response.getEmail());
        assertEquals(Role.DEVELOPER, response.getRole());

        verify(userRepository).save(any(User.class));
        verify(passwordEncoder).encode("Password123");
    }

    @Test
    void register_shouldThrowException_whenEmailAlreadyExists() {

        RegisterRequest request = new RegisterRequest();
        request.setUsername("testuser");
        request.setEmail("test@example.com");
        request.setPassword("Password123");

        when(userRepository.existsByEmail(request.getEmail()))
                .thenReturn(true);

        assertThrows(
                UserAlreadyExistsException.class,
                () -> authService.register(request)
        );

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void register_shouldThrowException_whenUsernameAlreadyExists() {

        RegisterRequest request = new RegisterRequest();
        request.setUsername("testuser");
        request.setEmail("test@example.com");
        request.setPassword("Password123");

        when(userRepository.existsByEmail(request.getEmail()))
                .thenReturn(false);

        when(userRepository.existsByUsername(request.getUsername()))
                .thenReturn(true);

        assertThrows(
                UserAlreadyExistsException.class,
                () -> authService.register(request)
        );

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void login_shouldReturnAuthResponse_whenCredentialsAreValid() {

        LoginRequest request = new LoginRequest();
        request.setUsernameOrEmail("testuser");
        request.setPassword("Password123");

        when(userRepository.findByUsernameOrEmail(
                "testuser",
                "testuser"
        )).thenReturn(Optional.of(user));

        when(passwordEncoder.matches(
                "Password123",
                "encodedPassword"
        )).thenReturn(true);

        when(jwtService.generateToken(
                "testuser",
                "DEVELOPER"
        )).thenReturn("mock-jwt-token");

        AuthResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("testuser", response.getUsername());
        assertEquals("test@example.com", response.getEmail());
        assertEquals(Role.DEVELOPER, response.getRole());
        assertEquals("mock-jwt-token", response.getToken());

        verify(passwordEncoder)
                .matches("Password123", "encodedPassword");

        verify(jwtService)
                .generateToken("testuser", "DEVELOPER");
    }

    @Test
    void login_shouldThrowException_whenUserDoesNotExist() {

        LoginRequest request = new LoginRequest();
        request.setUsernameOrEmail("unknown");
        request.setPassword("Password123");

        when(userRepository.findByUsernameOrEmail(
                "unknown",
                "unknown"
        )).thenReturn(Optional.empty());

        assertThrows(
                InvalidCredentialsException.class,
                () -> authService.login(request)
        );

        verify(passwordEncoder, never())
                .matches(anyString(), anyString());

        verify(jwtService, never())
                .generateToken(anyString(), anyString());
    }

    @Test
    void login_shouldThrowException_whenPasswordIsIncorrect() {

        LoginRequest request = new LoginRequest();
        request.setUsernameOrEmail("testuser");
        request.setPassword("WrongPassword");

        when(userRepository.findByUsernameOrEmail(
                "testuser",
                "testuser"
        )).thenReturn(Optional.of(user));

        when(passwordEncoder.matches(
                "WrongPassword",
                "encodedPassword"
        )).thenReturn(false);

        assertThrows(
                InvalidCredentialsException.class,
                () -> authService.login(request)
        );

        verify(jwtService, never())
                .generateToken(anyString(), anyString());
    }
}