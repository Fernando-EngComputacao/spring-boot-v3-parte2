package med.voll.api.assets.controller;

import jakarta.validation.Valid;
import med.voll.api.domain.user.AuthenticationData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationManager manager;

    @PostMapping
    public ResponseEntity loginEffect(@RequestBody @Valid AuthenticationData data) {
        var token = new UsernamePasswordAuthenticationToken(data.username(), data.password());
        Authentication auth = manager.authenticate(token);

        return ResponseEntity.ok().build();
    }
}