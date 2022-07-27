package app.springSecurity.controllers;


import app.springSecurity.Repo.RoleRepo;
import app.springSecurity.Repo.UserRepo;
import app.springSecurity.entities.AppRole;
import app.springSecurity.entities.RolesUserInfo;
import app.springSecurity.entities.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping(value = "/sessions")
/*@AllArgsConstructor
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
    public List<AppRole> getRoles(){
        return roleRepo.findAll();
    }
    @GetMapping(value = "/users")
    public List<AppUser> getUsers(){
        return userRepo.findAll();
    }
    @PostMapping(value = "/addRole")
    public AppRole addRole(@RequestBody AppRole role){
        return  roleRepo.save(role);
    }
    @PostMapping(value = "/addUser")
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

}

