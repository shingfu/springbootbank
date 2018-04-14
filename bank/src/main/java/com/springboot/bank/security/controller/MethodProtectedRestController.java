package com.springboot.bank.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * 测试控制器
 */
@RestController
@RequestMapping("/api")
public class MethodProtectedRestController {

  @RequestMapping(value = "/protectadmin", method = RequestMethod.GET)
  public ResponseEntity<?> getProtectAdmin() {
    return ResponseEntity.ok("Greeting from admin protected method.");
  }

  @RequestMapping(value = "/protectmanager", method = RequestMethod.GET)
  public ResponseEntity<?> getProtectManager() {
    return ResponseEntity.ok("Greeting from manager protected method.");
  }

  @RequestMapping(value = "/protectclerk", method = RequestMethod.GET)
  public ResponseEntity<?> getProtectClerk() {
    return ResponseEntity.ok("Greeting from clerk protected method.");
  }
}
