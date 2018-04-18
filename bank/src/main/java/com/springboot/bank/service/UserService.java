package com.springboot.bank.service;

import com.springboot.bank.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true, propagation = Propagation.NOT_SUPPORTED)
public class UserService {
  @Autowired
  private UserMapper userMapper;

  @Transactional(propagation = Propagation.REQUIRED, rollbackFor = Exception.class)
  public int changePassword(Integer id,
                            String password) {
    return userMapper.changePassword(id, password);
  }
}
