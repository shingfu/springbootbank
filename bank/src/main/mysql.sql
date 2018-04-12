
-- bank script of bank

-- 用户表
CREATE TABLE user
(
    id bigint PRIMARY KEY AUTO_INCREMENT,
    username varchar(100),
    password varchar(100),
    email varchar(100),
    enabled int, -- 1 启用 0 禁用
    last_password_reset_date datetime,
    login_time datetime
);

-- 角色表
CREATE TABLE AUTHORITY
(
    id bigint PRIMARY KEY AUTO_INCREMENT,
    name varchar(100),
    descn varchar(100)
);

-- 用户-角色表
CREATE TABLE USER_AUTHORITY
(
    user_id bigint,
    authority_id bigint,
    CONSTRAINT UA_USER_fk FOREIGN KEY (user_id) REFERENCES user (id),
    CONSTRAINT UA_AUTHORITY_fk FOREIGN KEY (authority_id) REFERENCES authority (id)
);





