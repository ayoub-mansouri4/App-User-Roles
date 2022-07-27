package app.springSecurity.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.NoArgsConstructor;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
             //lire le token
        String authorizationToken=request.getHeader("Authorization");
        //Bearer(porteur) est un prefix liée au token
        if(authorizationToken!=null && authorizationToken.startsWith("Bearer ")){
            try {
                   String jwt =authorizationToken.substring(7);
                   Algorithm algorithm=Algorithm.HMAC256("mns");
                   JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                   DecodedJWT decodedJWT= jwtVerifier.verify(jwt);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }
}
