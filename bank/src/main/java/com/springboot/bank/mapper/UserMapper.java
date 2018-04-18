package com.springboot.bank.mapper;

import com.springboot.bank.domain.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Update;

/**
 * @author SONG
 */
public interface UserMapper {

  User findByUsername(@Param("username") String username);

  @Update("update user set password=#{password},last_password_reset_date=now() where id=#{id}")
  int changePassword(@Param("id") Integer id,
                     @Param("password") String password);

}
