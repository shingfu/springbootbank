package com.springboot.bank;

import com.springboot.bank.domain.User;
import com.springboot.bank.service.UserService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ApplicationTests {

  @Autowired
  private UserService userService;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Test
  public void getPassword() {
    /**
     * 任何应用考虑到安全,绝不能明文的方式保存密码。
     * 密码应该通过哈希算法进行加密。
     * 有很多标准的算法比如SHA或者MD5,结合salt(盐)是一个不错的选择。
     * Spring Security 提供了BCryptPasswordEncoder类,
     * 实现Spring的PasswordEncoder接口使用BCrypt强哈希方法来加密密码。
     *
     * BCrypt强哈希方法:每次加密的结果都不一样。
     */
    System.out.println(passwordEncoder.encode("admin"));
  }

  @Test
  public void addUserAuthority() {
    userService.addUserAuthority(6, new Integer[]{3, 2});
  }

  @Test
  public void find() {
    for (int i = 0; i < 3; i++) {
      List<User> users = userService.find();
      users.forEach(user -> {
        System.out.println(user.getUsername() + " " + user.getEmail());
      });
    }

    /*
    for(User user : users){
      System.out.println(user.getUsername() + " " + user.getEmail());
    }*/
  }
}
