package com.springboot.bank.security.domain;

import com.springboot.bank.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT 用户工厂类
 *
 * @author SONG
 */
public final class JwtUserFactory {
  private JwtUserFactory() {

  }

  public static JwtUser create(User user) {
    return new JwtUser(
        user.getId(),
        user.getUsername(),
        user.getPassword(),
        user.getEmail(),
        mapToGrantedAuthority(user.getAuthorities()),
        user.getEnabled() == 1 ? true : false,
        user.getLastPasswordResetDate(),
        user.getLoginDate()
    );
  }

  private static List<GrantedAuthority> mapToGrantedAuthority(
      List<Authority> authorities
  ) {
    /*
    for(Authority authority:authorities){
    }*/
    return authorities.stream().
        map(authority -> new SimpleGrantedAuthority(authority.getName().name())).
        collect(Collectors.toList());
  }
}
