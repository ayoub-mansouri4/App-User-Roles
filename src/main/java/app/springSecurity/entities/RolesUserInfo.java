package app.springSecurity.entities;

import lombok.Data;

import java.util.List;

@Data
public class RolesUserInfo {
    AppUser user;
    List<AppRole> roles;
}