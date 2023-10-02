package med.voll.api.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import med.voll.api.assets.repository.UserRepository;
import med.voll.api.assets.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;
    @Autowired
    private UserRepository userRespository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            var tokenJWT = retrieveTokenJWT(request);
            if (tokenJWT != null) {
                var subject = tokenService.getSubject(tokenJWT);
                var user = userRespository.findByUsername(subject);
                var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

//            log.info("\n**[SECURITY-FILTER] <subject> {}",subject);
        filterChain.doFilter(request, response);
    }

    private String retrieveTokenJWT(HttpServletRequest request) {
        var authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null) {
            return authorizationHeader.replace("Bearer ","");
        }
        return null;

    }
}
