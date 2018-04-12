
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



-- 初始化数据 --------------------------------
-- 角色表
INSERT INTO employee.authority (id, name, descn) VALUES (1, 'ROLE_ADMIN', '系统管理员');
INSERT INTO employee.authority (id, name, descn) VALUES (2, 'ROLE_MANAGER', '经理');
INSERT INTO employee.authority (id, name, descn) VALUES (3, 'ROLE_CLERK', '办事员');

-- 用户表
INSERT INTO employee.user (id, username, password, email, enabled, last_password_reset_date, login_time) VALUES (1, 'admin', '$2a$10$N/AE4qqFef7n.ExfspTgx.x8pnrIjYrbwbe7BO5/CtyiylN3Lxpkm', 'admin@gmail.com', 1, '2018-04-10 07:05:33', '2018-04-12 07:05:48');
INSERT INTO employee.user (id, username, password, email, enabled, last_password_reset_date, login_time) VALUES (2, 'king', '$2a$10$zcnzVpqsczQgk09gCkHtjeeEmj9sz.a0wzm/KGWRlEdVI7L1M00Iy', 'king@gmail.com', 1, '2018-04-09 07:07:30', '2018-04-12 07:07:36');
INSERT INTO employee.user (id, username, password, email, enabled, last_password_reset_date, login_time) VALUES (3, 'smith', '$2a$10$CZdRDaFlpUtlkjI0im8P1eES9RJ8FVRWOV.rYEJzbnua/Yfczwuua', 'smith@gmail.com', 0, '2018-04-08 07:07:59', '2018-04-12 07:08:08');
INSERT INTO employee.user (id, username, password, email, enabled, last_password_reset_date, login_time) VALUES (4, 'jones', '$2a$10$xaZ5QgvBR8OPR8G6bxiaRe8IDepZ0xEfkUtqjfiFbdh1m3vUmEn92', 'jones@gmail.com', 1, '2018-04-10 07:08:47', '2018-04-12 07:08:56');
INSERT INTO employee.user (id, username, password, email, enabled, last_password_reset_date, login_time) VALUES (5, 'james', '$2a$10$KOrt2hsKVWdRMleKgYlmyuOIWUtiBA.v8n5tO3ObJ6NBydFDN2wNS', 'james@gmail.com', 1, '2018-04-12 07:09:28', '2018-04-12 07:09:33');


-- 用户-角色表
INSERT INTO employee.user_authority (user_id, authority_id) VALUES (1, 1);
INSERT INTO employee.user_authority (user_id, authority_id) VALUES (1, 2);
INSERT INTO employee.user_authority (user_id, authority_id) VALUES (1, 3);
INSERT INTO employee.user_authority (user_id, authority_id) VALUES (2, 1);
INSERT INTO employee.user_authority (user_id, authority_id) VALUES (3, 1);
INSERT INTO employee.user_authority (user_id, authority_id) VALUES (4, 2);
INSERT INTO employee.user_authority (user_id, authority_id) VALUES (4, 3);
INSERT INTO employee.user_authority (user_id, authority_id) VALUES (5, 3);
commit;

