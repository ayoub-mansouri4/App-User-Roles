package app.springSecurity.Repo;

import app.springSecurity.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepo extends JpaRepository<AppRole,Long> {
    public AppRole findRoleByRoleName(String roleName);
}
