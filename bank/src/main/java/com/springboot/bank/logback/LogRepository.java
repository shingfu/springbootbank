package com.springboot.bank.logback;

import org.springframework.data.mongodb.repository.MongoRepository;

/**
 * @author SONG
 */
public interface LogRepository extends MongoRepository<MyLog, String> {
}
