
@Copyright by SONG

Spring Boot Project: bank
技术栈: Spring Boot + Mybatis + MySQL

init project:
1.Create New Project - Empty Project - New Modules
2.配置 Database: MySQL
3.修改文件名或后缀名
  application.yml
  Application.java
  ApplicationTests.java
4.修改 pom.xml 新增依赖包
5.修改 application.yml 设置云端服务器端口 + datasource + mybatis
6.修改 Application.java 新增 @MapperScan




问题:
未登录可以访问 http://127.0.0.1:8080/ticket/welcome.html

在编写Web应用时，经常需要对页面做一些安全控制，比如：对于没有访问权限的用户需要转到登录表单页面。要实现访问控制的方法多种多样，可以通过Aop、拦截器实现，也可以通过框架实现（如：Apache Shiro、Spring Security）

Spring Security 是一个专门针对基于Spring的项目的安全框架,主要是利用了 AOP(Spring基础配置)来实现的。



JWT和Spring Security保护REST API

通常情况下，把API直接暴露出去是风险很大的，不说别的，直接被机器攻击就喝一壶的。那么一般来说，对API要划分出一定的权限级别，然后做一个用户的鉴权，依据鉴权结果给予用户开放对应的API。目前，比较主流的方案有几种:

用户名和密码鉴权，使用Session保存用户鉴权结果。
使用OAuth进行鉴权（其实OAuth也是一种基于Token的鉴权，只是没有规定Token的生成方式）
自行采用Token进行鉴权

第一种就不介绍了，由于依赖Session来维护状态，也不太适合移动时代，新的项目就不要采用了。第二种OAuth的方案和JWT都是基于Token的，但OAuth其实对于不做开放平台的公司有些过于复杂。我们主要介绍第三种：JWT。

什么是JWT？
JWT是 Json Web Token 的缩写。它是基于 RFC 7519 标准定义的一种可以安全传输的 小巧 和 自包含 的JSON对象。由于数据是使用数字签名的，所以是可信任的和安全的。JWT可以使用HMAC算法对secret进行加密或者使用RSA的公钥私钥对来进行签名。

JWT的工作流程
下面是一个JWT的工作流程图。模拟一下实际的流程是这样的（假设受保护的API在/protected中）

1.用户导航到登录页，输入用户名、密码，进行登录
2.服务器验证登录鉴权，如果用户合法，根据用户的信息和服务器的规则生成JWT Token
3.服务器将该token以json形式返回（不一定要json形式，这里说的是一种常见的做法）
4.用户得到token，存在localStorage、cookie或其它数据存储形式中。
5.以后用户请求/protected中的API时，在请求的header中加入 Authorization: Bearer xxxx(token)。此处注意token之前有一个7字符长度的 Bearer
6.服务器端对此token进行检验，如果合法就解析其中内容，根据其拥有的权限和自己的业务逻辑给出对应的响应结果。
7.用户取得结果

Spring Security是一个基于Spring的通用安全框架

如何利用Spring Security和JWT一起来完成API保护

简单的背景知识
如果你的系统有用户的概念的话，一般来说，你应该有一个用户表，最简单的用户表，应该有三列：Id，Username和Password，类似下表这种

ID	USERNAME	PASSWORD
10	wang	abcdefg
而且不是所有用户都是一种角色，比如网站管理员、供应商、财务等等，这些角色和网站的直接用户需要的权限可能是不一样的。那么我们就需要一个角色表：

ID	ROLE
10	USER
20	ADMIN
当然我们还需要一个可以将用户和角色关联起来建立映射关系的表。

USER_ID	ROLE_ID
10	10
20	20

00.参考 main/mysql.sql
01.pom.xml中新增依赖 spring-boot-starter-security
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
  </dependency>
02.配置application.properties
  server.context-path=
  spring.jackson.serialization.indent_output=true
  logging.level.org.springframework.security=info

  WebSecurityConfig: 初始化密码

03.新增 AuthorityName + Authority + 修改 Admins

04.安全服务的用户: JwtUser + JwtUserFactory + JwtUserDetailsServiceImpl + JwtAuthenticationResponse
  需要实现UserDetails接口,用户实体即为Spring Security所使用的用户

  配置 application.properties 支持 mybatis 映射文件 xml
  mybatis.mapper-locations=classpath:mybatis/mapper/*.xml

05.让Spring控制的安全配置类:WebSecurityConfig
 配置Spring Security - WebSecurityConfig
    1.当要自定义Spring Security的时候需要继承自WebSecurityConfigurerAdapter来完成,相关配置重写对应方法即可。
    2.在这里注册CustomUserService的Bean，然后通过重写configure方法添加自定义的认证方式。
    3.在configure(HttpSecurity http)方法中，设置了登录页面，而且登录页面任何人都可以访问，然后设置了登录失败地址，也设置了注销请求，注销请求也是任何人都可以访问的。
    4.permitAll表示该请求任何人都可以访问，.anyRequest().authenticated(),表示其他的请求都必须要有权限认证。
    5.这里可以通过匹配器来匹配路径，比如antMatchers方法，假设要管理员才可以访问admin文件夹下的内容，可以这样来写：.antMatchers("/admin/**").hasRole("ROLE_ADMIN")，也可以设置admin文件夹下的文件可以有多个角色来访问，写法如下：.antMatchers("/admin/**").hasAnyRole("ROLE_ADMIN","ROLE_USER")
    6.可以通过hasIpAddress来指定某一个ip可以访问该资源,假设只允许访问ip为210.210.210.210的请求获取admin下的资源，写法如下.antMatchers("/admin/**").hasIpAddress("210.210.210.210")
    7.更多的权限控制方式
      方法名                      用途
      access(String)              String EL表达式结果为true时可访问
      anonymous()                 匿名可访问
      denyAll()                   用户不可以访问
      fullyAuthenticated()        用户完全认识可访问(非remember me下自动登录)
      hasAnyAuthority(String...)  参数中任意权限的用户可访问
      hasAnyRole(String...)       参数中任意角色的用户可访问
      hasAuthority(String)        某一权限的用户可访问
      hasRole(String)             某一角色的用户可访问
      permitAll()                 所有用户可访问
      rememberMe()                运行通过 remember me 登录的用户访问
      authenticated()             用户登录后可访问
      hasIpAddress(String)        用户来自参数中的ip时可访问

    8.这里还可以做更多的配置，参考如下代码：
    http.authorizeRequests()
      .anyRequest().authenticated()
      .and().formLogin().loginPage("/login")
      //设置默认登录成功跳转页面
      .defaultSuccessUrl("/index").failureUrl("/login?error").permitAll()
      .and()
      //开启cookie保存用户数据
      .rememberMe()
      //设置cookie有效期
      .tokenValiditySeconds(60 * 60 * 24 * 7)
      //设置cookie的私钥
      .key("")
      .and()
      .logout()
      //默认注销行为为logout，可以通过下面的方式来修改
      .logoutUrl("/custom-logout")
      //设置注销成功后跳转页面，默认是跳转到登录页面
      .logoutSuccessUrl("")
      .permitAll();


06.在 XxxController 加一个修饰符 @PreAuthorize("hasRole('ADMIN')") 表示这个资源只能被拥有 ADMIN 角色的用户访问
  /**
   * 在 @PreAuthorize 中可以利用内建的 SPEL 表达式：比如 'hasRole()' 来决定哪些用户有权访问。
   * 需注意的一点是 hasRole 表达式认为每个角色名字前都有一个前缀 'ROLE_'。所以这里的 'ADMIN' 其实在
   * 数据库中存储的是 'ROLE_ADMIN' 。这个 @PreAuthorize 可以修饰Controller也可修饰Controller中的方法。
   **/

07.除了 /api/users, /api/imagecode, /api/global_json 外
  访问抛异常: org.springframework.security.access.AccessDeniedException: Access is denied


集成 JWT 和 Spring Security
07.pom.xml中新增依赖 jjwt 依赖
  <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt -->
  <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt</artifactId>
      <version>0.9.0</version>
  </dependency>

  <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-mobile</artifactId>
  </dependency>

  <!-- https://mvnrepository.com/artifact/com.google.code.findbugs/findbugs -->
  <dependency>
      <groupId>com.google.code.findbugs</groupId>
      <artifactId>findbugs</artifactId>
      <version>3.0.1</version>
  </dependency>


08.application.properties 配置 JWT

09.新建一个filter: JwtAuthenticationTokenFilter
  JwtAuthenticationEntryPoint + JwtAuthenticationRequest + JwtTokenUtil

10.在 WebSecurityConfig 中注入这个filter, 并且配置到 HttpSecurity 中

完成鉴权(登录),注册和更新token的功能
11.AuthenticationRestController + MethodProtectedRestController + UserRestController

12.更新初始化密码:AdminsTest.getPassword()
  任何应用考虑到安全,绝不能明文的方式保存密码。
  密码应该通过哈希算法进行加密。
  有很多标准的算法比如SHA或者MD5,结合salt(盐)是一个不错的选择。
  Spring Security 提供了BCryptPasswordEncoder类,
  实现Spring的PasswordEncoder接口使用BCrypt强哈希方法来加密密码。

  BCrypt强哈希方法:每次加密的结果都不一样。

  postmain test:http://127.0.0.1:8086/api/auth

13.前端:
  测试jwt: http://127.0.0.1:8080/jwt/

  重构代码: 登录 + 注销 + 修改密码 + 图表
  新增js: jwt-decode.min.js
  修改登录: index.html + hospital.js
  修改 CorsConfig: 注释 跨域session共享; 新增 addAllowedOrigin()
  修改注销: main.html