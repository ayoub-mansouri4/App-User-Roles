package app.springSecurity.Repo;

import app.springSecurity.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<AppUser,Long> {
    public AppUser findUserByUsername(String username);

}
