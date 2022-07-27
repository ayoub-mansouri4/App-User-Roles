package app.springSecurity.controllers;


import app.springSecurity.repo.RoleRepo;
import app.springSecurity.repo.UserRepo;
import app.springSecurity.entities.AppRole;
import app.springSecurity.entities.RolesUserInfo;
import app.springSecurity.entities.AppUser;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import java.util.*;
import java.util.stream.Collectors;

@RestController
/*
@RequestMapping(value = "/sessions")
@AllArgsConstructor
@NoArgsConstructor!*/
@Transactional
public class SessionsController {
    @Autowired
    UserRepo userRepo;
    @Autowired
    RoleRepo roleRepo;
    @Autowired
    PasswordEncoder passwordEncoder;


    @GetMapping(value ="/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public List<AppRole> getRoles(){
        return roleRepo.findAll();
    }
    @GetMapping(value = "/users")
    @PostAuthorize("hasAuthority(' @PostAuthorize(\"hasAuthority('USER')\")')")
    public List<AppUser> getUsers(){
        return userRepo.findAll();
    }
    @PostMapping(value = "/addRole")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole addRole(@RequestBody AppRole role){
        return  roleRepo.save(role);
    }
    @PostMapping(value = "/addUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser addUser(@RequestBody AppUser user){
        user.setRoles(new ArrayList<AppRole>());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }
    @PostMapping(value = "/addRolesToUser")
    public boolean addRolesToUser(@RequestBody RolesUserInfo rolesUserInfo) {
        if (rolesUserInfo.getRoles() == null || rolesUserInfo.getUser()==null) {
            return false;
        }
        AppUser user = rolesUserInfo.getUser();
        /*List<Role> new_roles = Stream.concat(user.getRoles().stream(), rolesUserInfo.getRoles().stream())
                .collect(Collectors.toList());*/
        user.setRoles(rolesUserInfo.getRoles());
         userRepo.save(user);
        return  true;
    }
    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws  Exception{
        String authToken=request.getHeader("Authorization");
        //Bearer(porteur) est un prefix liée au token
        if(authToken!=null && authToken.startsWith("Bearer ")){
            try {
                String JWTRefreshToken =authToken.substring(7);
                Algorithm algoSignature=Algorithm.HMAC256("mns");
                JWTVerifier jwtVerifier = JWT.require(algoSignature).build();
                //récuperer les claims(contenu du jwt)
                DecodedJWT decodedJWT= jwtVerifier.verify(JWTRefreshToken);
                String username=decodedJWT.getSubject();

                AppUser appUser=userRepo.findUserByUsername(username);
                String JWTAccessToken= JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+10*60*1000))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algoSignature);

                Map<String,String> idToken=new HashMap();
                idToken.put("access-token",JWTAccessToken);
                idToken.put("refresh-token",JWTRefreshToken);
                response.setContentType("application/json");
                //je vais envoyer le idToken dans la reponse de la requete et sous Format Json
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);

            }catch (Exception e){
                throw e;
            }

        }else {
           throw new  RuntimeException("Refresh token is required");

        }
    }

}

