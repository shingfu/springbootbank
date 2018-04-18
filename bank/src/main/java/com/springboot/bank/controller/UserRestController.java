package com.springboot.bank.controller;

import javax.servlet.http.HttpServletRequest;

import com.springboot.bank.security.JwtTokenUtil;
import com.springboot.bank.security.domain.JwtUser;
import com.springboot.bank.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

/**
 * 获取已授权用户信息
 *
 * @author SONG
 */
@RestController
@RequestMapping("/api")
public class UserRestController {

  @Value("${jwt.header}")
  private String tokenHeader;

  @Autowired
  private JwtTokenUtil jwtTokenUtil;

  @Autowired
  @Qualifier("jwtUserDetailsService")
  private UserDetailsService userDetailsService;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Autowired
  private UserService userService;

  @RequestMapping(value = "/user", method = RequestMethod.GET)
  public JwtUser getAuthenticatedUser(HttpServletRequest request) {
    String token = request.getHeader(tokenHeader).substring(7);
    String username = jwtTokenUtil.getUsernameFromToken(token);
    JwtUser user = (JwtUser) userDetailsService.loadUserByUsername(username);
    return user;
  }

  @RequestMapping(value = "changepassword", method = RequestMethod.POST)
  public ResponseEntity<?> changePassword(
      @RequestParam("password") String password,
      HttpServletRequest request
  ) {
    password = passwordEncoder.encode(password);

    String token = request.getHeader(tokenHeader).substring(7);
    String username = jwtTokenUtil.getUsernameFromToken(token);
    JwtUser user = (JwtUser) userDetailsService.loadUserByUsername(username);
    int count = userService.changePassword(user.getId(), password);
    return ResponseEntity.ok(count);
  }

}
