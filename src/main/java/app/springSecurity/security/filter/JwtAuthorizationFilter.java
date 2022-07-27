package app.springSecurity.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.NoArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;


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
                   //récuperer les claims(contenu du jwt)
                   DecodedJWT decodedJWT= jwtVerifier.verify(jwt);
                   String username=decodedJWT.getSubject();
                   String[] roles=decodedJWT.getClaim("roles").asArray(String.class);
                   Collection<GrantedAuthority> authorities= new ArrayList<>();
                   for (String role : roles) {
                        authorities.add(new SimpleGrantedAuthority(role));
                   }
                 //password est null
                UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(username,null,authorities);
                //mettre le user dans le context du spring security
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
               //si les verification passent bien alors passer au next filter
                filterChain.doFilter(request,response);
            }catch (Exception e){
                response.setHeader("error-message",e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }

        }else {
            filterChain.doFilter(request,response);

        }
    }
}
