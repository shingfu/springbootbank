package com.springboot.bank.domain;

import com.springboot.bank.security.domain.Authority;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

/**
 * 用户实体类
 *
 * @author SONG
 */
public class User implements Serializable {
  private static final long serialVersionUID = 3446748800973835540L;
  private Integer id;
  private String username;
  private String password;
  private String email;
  private Integer enabled;
  private Date lastPasswordResetDate;
  private Date loginDate;
  private List<Authority> authorities;

  public User() {
  }

  public Integer getId() {
    return id;
  }

  public void setId(Integer id) {
    this.id = id;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public Integer getEnabled() {
    return enabled;
  }

  public void setEnabled(Integer enabled) {
    this.enabled = enabled;
  }

  public Date getLastPasswordResetDate() {
    return lastPasswordResetDate;
  }

  public void setLastPasswordResetDate(Date lastPasswordResetDate) {
    this.lastPasswordResetDate = lastPasswordResetDate;
  }

  public Date getLoginDate() {
    return loginDate;
  }

  public void setLoginDate(Date loginDate) {
    this.loginDate = loginDate;
  }

  public List<Authority> getAuthorities() {
    return authorities;
  }

  public void setAuthorities(List<Authority> authorities) {
    this.authorities = authorities;
  }
}
