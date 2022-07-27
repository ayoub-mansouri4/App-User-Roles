package app.springSecurity.security.config;

import app.springSecurity.Repo.UserRepo;
import app.springSecurity.entities.AppUser;
import app.springSecurity.security.filter.JwtAuthenticationFilter;
import app.springSecurity.security.filter.JwtAuthorizationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
   @Autowired
    UserRepo userRepo;
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //lorsque le user  va saisir ses infos ,fait moi appel à la methode loadUserByUsername
        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser appUser = userRepo.findUserByUsername(username);
                Collection<GrantedAuthority> authorities=new ArrayList<>();
                appUser.getRoles().forEach(r->{
                    authorities.add(new SimpleGrantedAuthority(r.getRoleName()));
                        }
                );
                //voila l'user(Objet spring boot) qui va s'auth
                return new User(appUser.getUsername(), appUser.getPassword(),authorities);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      /*
        //to handle Whitelabel Error Page ==> disable la protection contre l'attack csrf
        //utilisable dans l'auth stateful et donc le server utilise les cookies et session(ID)
        //user a le droit de s'auth une seule fois et apres on accede à les ressources via la session
        http.csrf().disable();
       */
        //l'auth stateless n'utilise pas csrf elle utilise les tokens
        http.csrf().disable();

        //utilisation de l'auth stateless
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        //désactiver la protection contre les frames(l'apparition des div)
        http.headers().disable();

        //ajouter un filtre
        http.addFilter(new JwtAuthenticationFilter());
        //le 1er filtre qui va s'executer
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

       /*
        //activer un form d'auth
        //ne sera plus utilisable dans une auth stateful
        //car les sessions ne seront plus créées apres la validation du form
        http.formLogin();

        */

        //toutes les ressources necessitent une auth
        http.authorizeRequests().anyRequest().authenticated();

        /*
        //autoriser une ressource
        http.authorizeRequests().antMatchers("/pathRousource").permitAll();
         */


         /*toutes les requetes ne necessitent pas une auth
        http.authorizeRequests().anyRequest().permitAll();*/
    }
}
