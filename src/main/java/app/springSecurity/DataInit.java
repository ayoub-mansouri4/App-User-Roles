package app.springSecurity;

import app.springSecurity.repo.RoleRepo;
import app.springSecurity.repo.UserRepo;
import app.springSecurity.entities.AppRole;
import app.springSecurity.entities.AppUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;


@Component
public class DataInit implements CommandLineRunner {
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private RoleRepo roleRepo;


    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        roleRepo.save(new AppRole("ADMIN"));
        roleRepo.save(new AppRole("USER"));
        AppRole roleAdmin=roleRepo.findRoleByRoleName("ADMIN");
        AppRole roleUser=roleRepo.findRoleByRoleName("USER");


        List<AppRole> roleList=new ArrayList<AppRole>();
        roleList.add(roleAdmin);

        AppUser user1=new AppUser("user1",passwordEncoder.encode("1234"));
        AppUser user2=new AppUser("user2",passwordEncoder.encode("1234"));
       /* User user3=new User("ayoub3","1234");
        User user4=new User("ayoub4","1234");*/


        user1.setRoles(roleList);
        userRepo.save(user1);
        roleList.clear();
        roleList.add(roleUser);
        user2.setRoles(roleList);
        userRepo.save(user2);





    }
}
