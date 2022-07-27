package app.springSecurity.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.crypto.AlgorithmMethod;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("attemptAuthentication");
        String  username=request.getParameter("username");
        String  password=request.getParameter("password");
        UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(username,password);

        //declancher l'operation d'auth(UserDetailsService -> DB , voir diagramme de sequence)
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        //Authentication authResult ce parametre contient le resultat d'auth
        //authResult.getPrincipal() return user qui est s'auth
        User user=(User) authResult.getPrincipal();
        Algorithm algoSignature =Algorithm.HMAC256("mns");
        //le access token doit etre actualiser pour chaque 5 min
        //et donc ona besoin d'un refresh token(eviter le changement des roles,long durée)
        String JWTAccessToken= JWT.create()
                .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+5*60*1000))
                                .withIssuer(request.getRequestURL().toString())
                                        .withClaim("roles",user.getAuthorities().stream().map(ga->ga.getAuthority()).collect(Collectors.toList()))
                                          .sign(algoSignature);

       //1erement je verifie refreshtokent et puis access token                                         .sign(algoSignature);
        String JWTRefreshToken= JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+15*60*1000)) //15 min
                .withIssuer(request.getRequestURL().toString())
                .sign(algoSignature);
        Map idToken=new HashMap();
        idToken.put("access-token",JWTAccessToken);
        idToken.put("refresh-token",JWTRefreshToken);
        response.setContentType("application/json");
        //je vais envoyer le idToken dans la reponse de la requete et sous Format Json
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);
    }
}
