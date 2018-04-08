package com.oauth.oauthserver.dao;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.oauth.oauthserver.model.User;



@Repository
public interface UserDao extends CrudRepository<User, Long> {
    User findByUsername(String username);
}
