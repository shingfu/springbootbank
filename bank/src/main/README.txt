
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


跨域是指 不同域名之间相互访问。跨域，指的是浏览器不能执行其他网站的脚本。它是由浏览器的同源策略造成的，是浏览器对JavaScript施加的安全限制

也就是如果在A网站中，我们希望使用Ajax来获得B网站中的特定内容
如果A网站与B网站不在同一个域中，那么就出现了跨域访问问题。

什么是同一个域？
同一协议，同一ip，同一端口，三同中有一不同就产生了跨域。



配置前端服务器 Live-server:
  1 下载 nodejs: nodejs.org
  2 安装 nodejs
  3 安装前端服务器:npm --registry=https://registry.npm.taobao.org i -g live-server
  4 启动前端服务器:live-server


1.新增用户(系统用户) - ROLE_ADMIN
2.海量的数据 - redis

问题:
1.图表查询 N 次
2.高并发.txt


将Redis作为二级缓存
1.pom.xml中增加redis的依赖
  <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-redis</artifactId>
  </dependency>

2.application.properties中增加redis配置
  Spring Boot会在侦测到存在Redis的依赖并且Redis的配置是可用的情况下，使用RedisCacheManager初始化CacheManager

  spring.redis.pool.max-idle=8
  spring.redis.pool.min-idle=0
  spring.redis.pool.max-active=8
  spring.redis.pool.max-wait=-1

  logging.level.com.hospital.registration.mapper=debug

  采用yaml作为配置文件的格式。xml显得冗长，properties没有层级结构，yaml刚好弥补了这两者的缺点。
  这也是Spring Boot默认就支持yaml格式的原因

3.util:ApplicationContextHolder + RedisCache
4.映射器接口: @CacheNamespace(implementation = com.hospital.registration.util.RedisCache.class)
  映射文件 : <cache type="com.hospital.registration.util.RedisCache"/>
5.在Spring Boot主类 Application 中增加@EnableCaching注解开启缓存功能
6.JUnit



Mybatis的二级缓存原理:Mybatis的二级缓存可以自动地对数据库的查询做缓存，并且可以在更新数据时同时自动地更新缓存。

实现Mybatis的二级缓存很简单，只需要新建一个类实现org.apache.ibatis.cache.Cache接口即可。
该接口共有以下五个方法：

String getId()：mybatis缓存操作对象的标识符。一个mapper对应一个mybatis的缓存操作对象。
void putObject(Object key, Object value)：将查询结果塞入缓存。
Object getObject(Object key)：从缓存中获取被缓存的查询结果。
Object removeObject(Object key)：从缓存中删除对应的key、value。只有在回滚时触发。一般我们也可以不用实现，具体使用方式请参考：org.apache.ibatis.cache.decorators.TransactionalCache。
void clear()：发生更新时，清除缓存。
int getSize()：可选实现。返回缓存的数量。
ReadWriteLock getReadWriteLock()：可选实现。用于实现原子性的缓存操作

tips: 修改密码后需等缓存失效超时后,再重新登录



Cache注解详解

@CacheConfig：主要用于配置该类中会用到的一些共用的缓存配置。在这里@CacheConfig(cacheNames = "users")：配置了该数据访问对象中返回的内容将存储于名为users的缓存对象中，也可以不使用该注解，直接通过@Cacheable自己配置缓存集的名字来定义。

@Cacheable：配置了findByName函数的返回值将被加入缓存。同时在查询时，会先从缓存中获取，若不存在才再发起对数据库的访问。该注解主要有下面几个参数：

value、cacheNames：两个等同的参数（cacheNames为Spring 4新增，作为value的别名），用于指定缓存存储的集合名。由于Spring 4中新增了@CacheConfig，因此在Spring 3中原本必须有的value属性，也成为非必需项了
key：缓存对象存储在Map集合中的key值，非必需，缺省按照函数的所有参数组合作为key值，若自己配置需使用SpEL表达式，比如：@Cacheable(key = "#p0")：使用函数第一个参数作为缓存的key值，更多关于SpEL表达式的详细内容可参考官方文档
condition：缓存对象的条件，非必需，也需使用SpEL表达式，只有满足表达式条件的内容才会被缓存，比如：@Cacheable(key = "#p0", condition = "#p0.length() < 3")，表示只有当第一个参数的长度小于3的时候才会被缓存，若做此配置上面的AAA用户就不会被缓存，读者可自行实验尝试。
unless：另外一个缓存条件参数，非必需，需使用SpEL表达式。它不同于condition参数的地方在于它的判断时机，该条件是在函数被调用之后才做判断的，所以它可以通过对result进行判断。
keyGenerator：用于指定key生成器，非必需。若需要指定一个自定义的key生成器，我们需要去实现org.springframework.cache.interceptor.KeyGenerator接口，并使用该参数来指定。需要注意的是：该参数与key是互斥的
cacheManager：用于指定使用哪个缓存管理器，非必需。只有当有多个时才需要使用
cacheResolver：用于指定使用那个缓存解析器，非必需。需通过org.springframework.cache.interceptor.CacheResolver接口来实现自己的缓存解析器，并用该参数指定。
除了这里用到的两个注解之外，还有下面几个核心注解：

@CachePut：配置于函数上，能够根据参数定义条件来进行缓存，它与@Cacheable不同的是，它每次都会真是调用函数，所以主要用于数据新增和修改操作上。它的参数与@Cacheable类似，具体功能可参考上面对@Cacheable参数的解析
@CacheEvict：配置于函数上，通常用在删除方法上，用来从缓存中移除相应数据。除了同@Cacheable一样的参数之外，它还有下面两个参数：
allEntries：非必需，默认为false。当为true时，会移除所有数据
beforeInvocation：非必需，默认为false，会在调用方法之后移除数据。当为true时，会在调用方法之前移除数据。




在Spring Boot中到底使用了什么缓存呢？

在Spring Boot中通过@EnableCaching注解自动化配置合适的缓存管理器（CacheManager），Spring Boot根据下面的顺序去侦测缓存提供者：

Generic
JCache (JSR-107)
EhCache 2.x
Hazelcast
Infinispan
Redis
Guava
Simple
除了按顺序侦测外，也可以通过配置属性spring.cache.type来强制指定。可以通过debug调试查看cacheManager对象的实例来判断当前使用了什么缓存。




-------------------------------------------
背景
在分布式系统中，有多个web app，这些web app可能分别部署在不同的物理服务器上，并且有各自的日志输出。当生产问题来临时，很多时候都需要去各个日志文件中查找可能的异常，相当耗费人力。日志存储多以文本文件形式存在，当有需求需要对日志进行分析挖掘时，这个处理起来也是诸多不便，而且效率低下。

为了方便对这些日志进行统一管理和分析，可以将日志统一输出到指定的数据库系统中，再由日志分析系统去管理。由于这里是mongodb的篇章，所以主观上以mongodb来做日志数据存储；客观上，一是因为它轻便、简单，与log4j整合方便，对系统的侵入性低。二是因为它与大型的关系型数据库相比有很多优势，比如查询快速、bson存储结构利于扩展、免费等。


NoSQL & MongoDB



NoSQL:Not Only SQL (不只是SQL)

数据存储方案:
应用程序存储和检索数据有以下三种方案
文件系统直接存储
关系型数据库
NoSQL 数据库（是对非关系型数据库的统称）

最重要的差别是 NoSQL 不使用 SQL 作为查询语言。
数据存储可以不需要固定的表格模式（行和列），避免使用SQL的JOIN操作，有更高的性能及水平可扩展性的特征。
NoSQL 在 ACID（原子性、一致性、隔离性、持久性） 的支持方面没有传统关系型数据完整。

文档数据库   MongoDB / CouchDB
键／值数据库 redis   / Cassandra
列数据库     Hbase   / Cassandra
图数据库     Neo4J



MongoDB 基于文档存储模型，数据对象以BSON（二进制 JSON）格式被存储在集合的文档中，而不是关系数据库的行和列中。

集合
使用集合将数据编组，是一组用途相同的文档，类似表的概念，但集合不受模式的限制，在其中的文档格式可以不同。

文档
文档表示单个实体数据，类似一条记录（行）；与行的差别：行的数据是扁平的，每一列只有一个值，而文档中可以包含子文档，提供的数据模型与应用程序的会更加一致。


一个文档 Demo:
{
  name:'X Fimaly'
  address: ['NY','LA']
  person: [{'name':'Jack'},{'name':'Rose'}]
}



安装 MongoDB
官网:https://www.mongodb.com/

下载社区版:mongodb-win32-x86_64-3.4.9-signed.msi

设置环境变量:
把安装目录 mongodb/bin 添加到系统 path 中
...;D:\Program Files\MongoDB\Server\3.4\bin

cmd:
  mongo --help
  mongo --version

  tips:出错 缺少 api-ms-win-crt-runtime-xxx.dll 则安装 vc_redist.x64.exe

创建一个存放数据的目录如：D:/Oracle/MongoDB/data
从命令行执行 mongod --dbpath D:/Oracle/MongoDB/data 启动服务器 [不能关闭]
从命令行执行 mongo 启动交互窗口（mongoDB shell）



MongoDB 使用:
数据库:
启动 mongo shell  [相当于 mongo 客户端]

显示数据库
>show dbs

切换数据库（若不存在则创建数据库）
>use employee [相当于 mongo 的一个数据库]

显示当前使用的数据库
>db

删除当前数据库
  db.dropDatabase()



Collection(集合):
显示所有集合
>show collections

创建一个集合
db.createCollection('emps') [相当于一张表 emps]

删除一个集合
  db.emps.drop()



MongoDB CRUD:
插入一个文档
db.collection.insertOne()
db.emps.insertOne({name:'SMITH',age:27})

插入多个文档
db.collection.insertMany()
db.emps.insertMany([{name:'SCOTT',age:26},{name:'KING',age:24,phone:['155','186']}])

查询（检索文档）
db.emps.find()

name 是 KING
db.emps.find({name:'KING'})

age 大于 25
db.emps.find({age:{$gt:25}})

age 小于 25 且 name 是 KING
db.emps.find({age:{$lt:25},name:'KING'})

电话号码为 186
db.emps.find({phone:'186'})



更新一个文档
db.collection.updateOne()
更新多个文档
db.collection.updateMany()

db.emps.updateOne(
	{name:'SCOTT'},	// 更新的条件
	{$set:{age:19}}	// 新的数据
)

// update 时新增字段
db.emps.updateOne(
	{name:'SMITH'},
  {$set:{phoneabc:'186'}}
)



删除一个文档
db.collection.deleteOne()
删除多个文档
db.collection.deleteMany()

db.emps.deleteOne({name:'SCOTT'})
db.emps.deleteMany({age:{$lt:30}})


--------------------------------------------------------
准备:
1.start mysql [数据库服务器]
2.start redis [redis服务器 - 二级缓存]
  - 切换至 bin 目录,cmd 执行: redis-server.exe redis.windows.conf

  start MongoDB [日志服务器]
  - cmd 执行: mongod --dbpath D:/Oracle/MongoDB/data
3.start idea  [云端/后端服务器]
  - run Application
4.start live-server [前端服务器]
5.Chrome




使用logback实现http请求日志导入mongodb

spring boot自带logback作为其日志新系统，但是在实际工作中，常常需要对日志进行管理或分析，
如果只是单纯的将日志导入文本文件，则在查询时操作过于繁琐，
如果将其导入mysql等关系型数据库进行存储，又太影响系统性能，同时由于Mysql其结构化的信息存储结构，导致在存储时不够灵活。
因此，在此考虑将springboot系统中产出的日志(logback) 存入mongodb中

1.pom.xml 引入依赖
  https://mvnrepository.com 搜索最新的 jar 包
  <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-mongodb</artifactId>
  </dependency>

  <!-- AOP 依赖 -->
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-aop</artifactId>
    </dependency>

  <!-- https://mvnrepository.com/artifact/ch.qos.logback/logback-core -->
  <dependency>
    <groupId>ch.qos.logback</groupId>
    <artifactId>logback-core</artifactId>
    <version>1.2.3</version>
  </dependency>

  <!-- https://mvnrepository.com/artifact/ch.qos.logback/logback-classic -->
  <dependency>
    <groupId>ch.qos.logback</groupId>
    <artifactId>logback-classic</artifactId>
    <version>1.2.3</version>
  </dependency>

  <!-- https://mvnrepository.com/artifact/log4j/log4j -->
  <dependency>
      <groupId>log4j</groupId>
      <artifactId>log4j</artifactId>
      <version>1.2.17</version>
  </dependency>

2.添加实体类: logback.MyLog.java
3.添加数据访问接口: LogRepository.java
4.Appender 类: MongoDBAppender.java

5.切面中使用mongodb logger:
  logger取名为MONGODB
  通过getBasicDBObject函数从HttpServletRequest和JoinPoint对象中获取请求信息，并组装成BasicDBObject
  getHeadersInfo函数从HttpServletRequest中获取header信息
  通过logger.info()，输出BasicDBObject对象的信息到mongodb

6.resources/logback.xml - 更新 <appender name="MONGODB" />
            application.yml 配置spring boot的文件配置标签

            spring:
              data:
                mongodb:
                  uri: mongodb://127.0.0.1:27017/logs

7.controller

8.start Application
  Chrome: http://127.0.0.1:8080/mongo | greeting

9.cmd - mongo 进入客户端
  >use logs
  >db.myLog.find()
  >db.myLog.find({_class:"com.hospital.registration.logback.MyLog"})
