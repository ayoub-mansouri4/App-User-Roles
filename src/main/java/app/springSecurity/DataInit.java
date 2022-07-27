package app.springSecurity;

import app.springSecurity.Repo.RoleRepo;
import app.springSecurity.Repo.UserRepo;
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
        roleRepo.save(new AppRole("Admin"));
        roleRepo.save(new AppRole("RespoStagiaires"));
        roleRepo.save(new AppRole("RespoFormation"));
        roleRepo.save(new AppRole("RespoIncubation"));
        AppRole roleAdmin=roleRepo.findRoleByRoleName("Admin");
        AppRole roleRespoStagiaires=roleRepo.findRoleByRoleName("RespoFormation");
        AppRole roleRespoFormation=roleRepo.findRoleByRoleName("RespoFormation");
        AppRole roleRespoIncubation=roleRepo.findRoleByRoleName("RespoIncubation");

        List<AppRole> roleList=new ArrayList<AppRole>();
        roleList.add(roleAdmin);

        AppUser user1=new AppUser("ayoub1",passwordEncoder.encode("1234"));
        AppUser user2=new AppUser("ayoub2",passwordEncoder.encode("1234"));
       /* User user3=new User("ayoub3","1234");
        User user4=new User("ayoub4","1234");*/


        user1.setRoles(roleList);
        userRepo.save(user1);
        roleList.clear();
        roleList.add(roleRespoFormation);
        roleList.add(roleRespoStagiaires);
        user2.setRoles(roleList);
        userRepo.save(user2);





    }
}
