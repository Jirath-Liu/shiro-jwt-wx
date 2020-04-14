# 使用Shiro+JWT完成的微信小程序的登录

你也可以在csdn中查看讲解https://blog.csdn.net/weixin_44494373/article/details/105420417

微信小程序用户登陆，完整流程可参考下面官方地址，本例中是按此流程开发
https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html

# 你需要了解的点

微信小程序的登录流程

https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html

Shiro的基础知识

https://shiro.apache.org/10-minute-tutorial.html

JWT以及Token

https://jwt.io/introduction/

# 项目的流程

![未命名文件](https://img03.sogoucdn.com/app/a/100520146/2ad41dac304357cccec287a07dced25d)

1.  调用 wx.login() 获取 临时登录凭证code ，并回传到开发者服务器。
2.  访问login接口，并将code给后台
3.  被JwtShirioFilter拦截(在shiro配置中配置的)，查看有没有token在Header
4.  有则自动执行登录操作，核实token的合法性，并刷新token
5.  没有则被controller拦截进入service中进行登录
6.  使用code获取用户信息，默认初始化了一些信息（可以修改的）
7.  生成token（会存至redis）
8.  返回token

# 本项目的结构

项目分包：

1. conf 项目的配置
    -   exceptoionconfig 配置了异常的抛出，使用@ControllerAdvice进行拦截统一处理
    -   jwt 包含一个jwt工具类，在使用时会与redis连接，存储、验证与生成token
    -   shiro 是本项目配置的核心，其中关闭了session管理，使用jwt来完成验证，包含一个自定的应用于shiro的token
    -   RestTemplateConfig 使用Spring
2. enums 包含了需要的枚举类
3. vo
    -   wxapi 包含了一个请求微信后台需要的结果类

不可修改的模块：有JWT与Shiro的类别以及配置模块

# 具体实现

## 一、shiro基础配置

### 1.设置一个自己的realm进行token验证，用户登录会执行你的realm

在DefaultWebSecurityManager 中进行配置

realm是需要自己实现的，先让他在这里报错，当自己的提示也可以

````java
DefaultWebSecurityManager defaultWebSecurityManager=new DefaultWebSecurityManager(tokenRealm);
        //设置realm
        defaultWebSecurityManager.setRealm(tokenRealm);
````



### 2.我们需要关闭shiro的session功能

在DefaultWebSecurityManager 中进行配置

````java
 DefaultSubjectDAO subjectDAO = (DefaultSubjectDAO) defaultWebSecurityManager.getSubjectDAO();
        DefaultSessionStorageEvaluator evaluator = (DefaultSessionStorageEvaluator) subjectDAO.getSessionStorageEvaluator();
        evaluator.setSessionStorageEnabled(Boolean.FALSE)
````

### 3.设置realm

我们需要定制一个realm，并且为了能够被识别，选择继承AuthorizingRealm类

需要我们完成的模块：

1.  realm对请求的识别 **我们的方案是验证token是否为我们定制的token**
2.  审核信息 **其中有对token的验证，我们做在工具类中**
3.  身份/角色验证
4.  关闭密码校验加密

````java
@Component
public class TokenRealm extends AuthorizingRealm {
    @Autowired
    JwtUtil jwtUtil;

    /**
     * 该方法是为了判断这个主体能否被本Realm处理，判断的方法是查看token是否为同一个类型
     * @param authenticationToken
     * @return
     */
    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        return authenticationToken instanceof JwtShiroToken;
    }


    /**
     * 在需要验证身份进行登录时，会通过这个接口，调用本方法进行审核，将身份信息返回，有误则抛出异常，在外层拦截
     * @param authenticationToken 这里收到的是自定义的token类型，在JwtShiroToken中，自动向上转型。得到的getCredentials为String类型，可以使用toString
     * @return
     * @throws AuthenticationException token异常，可以细化设置
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) {
        String submittedToken=authenticationToken.getCredentials().toString();
        //解析出信息
        String wxOpenId = jwtUtil.getWxOpenIdByToken(submittedToken);
        String sessionKey = jwtUtil.getSessionKeyByToken(submittedToken);
        String userId=jwtUtil.getUserIdByToken(submittedToken);
        //对信息进行辨别
        if (StringUtils.isEmpty(wxOpenId)) {
            throw new TokenException("user account not exits , please check your token");
        }
        if (StringUtils.isEmpty(sessionKey)) {
            throw new TokenException("sessionKey is invalid , please check your token");
        }
        if (StringUtils.isEmpty(userId)) {
            throw new TokenException("userId is invalid , please check your token");
        }
        if (!jwtUtil.verifyToken(submittedToken)) {
            throw new TokenException("token is invalid , please check your token");
        }
        //在这里将principal换为用户的id
        return new SimpleAuthenticationInfo(userId, submittedToken, getName());
    }

    /**
     * 这个方法是用来添加身份信息的，本项目计划为管理员提供网站后台，所以这里不需要身份信息，返回一个简单的即可
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    /**
     * 注意坑点 : 密码校验 , 这里因为是JWT形式,就无需密码校验和加密,直接让其返回为true(如果不设置的话,该值默认为false,即始终验证不通过)
     */
    @Override
    public CredentialsMatcher getCredentialsMatcher() {
        return (token, info) -> true;
    }
}

````

### 4.定制一个token，继承AuthenticationToken

**默认的token是包含两个部分的，账号和密码（可以这样理解）**

**我们将这两个信息都调整为token**

```java
/**
 * @author Jirath
 * @date 2020/4/9
 * @description: 一个用于Shiro使用的Authentication，因为使用JWT需要有自己的身份信息，所以使用针对Token定制的信息
 */
@Data
public class JwtShiroToken implements AuthenticationToken {
    /**
     * 封装，防止误操作
     */
    private String token;

    /**
     * token作为两者进行提交，使用构造方法进行初始化
     * @param token 用户提交的token
     */
    public JwtShiroToken(String token){
        this.token=token;
    }
    /**
     * 在UserNamePasswordToken中，使用的是账号和密码来作为主体和签证,这里我们使用Token登录
     * 两者的get都是获取token
     */
    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}
```

### 5.上述提到了jwt的工具类，我们实现一下

1.  因为签名最好是自己定的，以备不时之需，你也可使用jwt框架随机一个，我们从配置文件中导入进来
2.  token生成模块，需要缓存redis
3.  token验证模块，需要使用redis进行续期
4.  token获取信息模块

````java
@Component
public class JwtUtil {
    /**
     * JWT 自定义密钥 在配置文件进行配置
     */
    @Value("${jwt.secret}")
    private String secretKey;

    /**
     * JWT 过期时间值 这里写死为和小程序时间一致 7200 秒，也就是两个小时
     */
    private static final long EXPIRE_TIME = 7200;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    /**
     * 根据微信用户登陆信息创建 token
     * 注 : 这里的token会被缓存到redis中,用作为二次验证
     * redis里面缓存的时间应该和jwt token的过期时间设置相同
     * @param useInfo 用户信息
     * @return 返回 jwt token
     */
    public String createTokenByWxAccount(User useInfo) {
        //JWT 随机ID,做为验证的key
        String jwtId = UUID.randomUUID().toString();
        //1 . 加密算法进行签名得到token
        //生成签名
        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        //生成token
        String token = JWT.create()
                .withClaim("wxOpenId", useInfo.getWxId())
                .withClaim("user-id",useInfo.getId())
                .withClaim("sessionKey", useInfo.getWxId())
                .withClaim("jwt-id", jwtId)
                //JWT 配置过期时间的正确姿势，因为单位是毫秒，所以需要乘1000
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRE_TIME * 1000))
                .sign(algorithm);
        //2 . Redis缓存JWT, 注 : 请和JWT过期时间一致
        stringRedisTemplate.opsForValue().set("JWT-SESSION-" + jwtId, token, EXPIRE_TIME, TimeUnit.SECONDS);
        return token;
    }

    /**
     * 校验token是否正确
     * 1 . 根据token解密，解密出jwt-id , 先从redis中查找出redisToken，匹配是否相同
     * 2 . 然后再对redisToken进行解密，解密成功则 继续流程 和 进行token续期
     *
     * @param token 密钥
     * @return 返回是否校验通过
     */
    public boolean verifyToken(String token) {
        try {
            //1 . 根据token解密，解密出jwt-id , 先从redis中查找出redisToken，匹配是否相同
            String redisToken = stringRedisTemplate.opsForValue().get("JWT-SESSION-" + getJwtIdByToken(token));
            if (!redisToken.equals(token)) {
                return false;
            }
            //2 . 得到算法相同的JWTVerifier
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("wxOpenId", getWxOpenIdByToken(redisToken))
                    .withClaim("user-id",getUserIdByToken(token))
                    .withClaim("sessionKey", getSessionKeyByToken(redisToken))
                    .withClaim("jwt-id", getJwtIdByToken(redisToken))
                    //续期
                    .acceptExpiresAt(System.currentTimeMillis() + EXPIRE_TIME * 1000)
                    .build();
            //3 . 验证token
            verifier.verify(redisToken);
            //4 . Redis缓存JWT续期
            stringRedisTemplate.opsForValue().set("JWT-SESSION-" + getJwtIdByToken(token), redisToken, EXPIRE_TIME, TimeUnit.SECONDS);
            return true;
        } catch (Exception e) { //捕捉到任何异常都视为校验失败
            return false;
        }
    }

    /**
     * 根据Token获取wxOpenId(注意坑点 : 就算token不正确，也有可能解密出wxOpenId,同下)
     */
    public String getWxOpenIdByToken(String token)  {
        return JWT.decode(token).getClaim("wxOpenId").asString();
    }

    /**
     * 根据Token获取sessionKey
     */
    public String getSessionKeyByToken(String token)  {
        return JWT.decode(token).getClaim("sessionKey").asString();
    }

    /**
     * 根据Token 获取jwt-id
     */
    public String getJwtIdByToken(String token)  {
        return JWT.decode(token).getClaim("jwt-id").asString();
    }
    /**
     * 根据Token 获取user-id
     */
    public String getUserIdByToken(String token)  {
        return JWT.decode(token).getClaim("user-id").asString();
    }

}
````

### 6.完成了jwt工具类的实现，我们回头继续进行shiro拦截器的配置

除了自带的拦截器以外，我们希望能自动扫描token，所以我们选择新建一个自己的拦截器，加入进来扫描所有的接口并放行，达到识别token并标记登录的需求。

````java
@Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(DefaultWebSecurityManager securityManager){
        ShiroFilterFactoryBean shiroFilterFactoryBean=new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        //注册拦截方案
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("token", new JwtShiroFilter());
        shiroFilterFactoryBean.setFilters(filterMap);
        //定义拦截规则
        Map<String, String> filterRuleMap = new HashMap<>();
        //登陆相关api不需要被过滤器拦截
        filterRuleMap.put("/api/wx/user/login/**", "anon");
        filterRuleMap.put("/api/response/**", "anon");
        // 所有请求通过JWT Filter
        filterRuleMap.put("/**", "token");
        return shiroFilterFactoryBean;
    }

````

### 7.编写拦截器

拦截器同样采用继承BasicHttpAuthenticationFilter，我们只需要进行微调即可使用

其中包含：

1.  判断是否进行拦截，这里建议查看BasicHttpAuthenticationFilter的源码，来理解getAuthzHeader所做的修改
2.  验证逻辑，被识别的请求会运行这个方法，在这里我们可以进行登录操作
3.  添加跨域支持

````java
/**
 * <h1>BasicHttpAuthenticationFilter</h1>
 * <p>shiro会扫描项目中所有的filter并加入manager中</p>
 * <p>所有的请求都会被拦截，在请求头前标了shiro定制的header的请求会被识别</p>
 * <h1>JwtFilter</h1>
 * <p>这里定制一个filter，使得我们可以识别出有token的请求</p>
 * <p><b>注意！登录是在这里进行的！isAccessAllowed方法，主要完成了登录</b></p>
 *  <p>因为小程序的访问不是同一次访问，所以对于系统来说，若把session替换为了token，就要每次登录
 * </p>
 * @author Jirath
 * @date 2020/4/9
 * @description: 定制一个使用jwt的filter
 */
public class JwtShiroFilter extends BasicHttpAuthenticationFilter {
    /**
     * 判断用户是否想要进行 需要验证的操作
     * 检测header里面是否包含token字段即可\
     * 调用情况请查看BasicHttpAuthenticationFilter源码
     */
    @Override
    protected String getAuthzHeader(ServletRequest request) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        return httpRequest.getHeader("token");
    }

    @Override
    protected boolean isLoginAttempt(String authzHeader) {
        return authzHeader != null;
    }

    /**
     * 此方法调用登陆，验证逻辑
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginAttempt(request, response)) {
            JwtShiroToken token = new JwtShiroToken(getAuthzHeader(request));
            getSubject(request, response).login(token);
        }
        return true;
    }

    /**
     * 提供跨域支持
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            httpServletResponse.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(request, response);
    }
}
````

### 8.完善shiro配置，加入注解等

````java
@Configuration
public class ShiroConf {
    /**
     * <h1>FactoryBean</h1>
     * FactoryBean to be used in Spring-based web applications for defining the master Shiro Filter.
     * <h1>factoryBean.setFilters</h1>
     * <p>Sets the filterName-to-Filter map of filters available for reference when creating filter chain definitions.
     * Note: This property is optional: this FactoryBean implementation will discover all beans in the web application context that implement the Filter interface and automatically add them to this filter map under their bean name.
     * </p>
     * <code>
     *  Map<String, Filter> filterMap = new HashMap<>();
     *  filterMap.put("jwt", new JwtFilter());
     *  factoryBean.setFilters(filterMap);
     * </code></br>
     * <p><b>上述代码的目的是生成自定义的filter用来过滤请求</b></p>
     * @param securityManager
     * @return
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(DefaultWebSecurityManager securityManager){
        ShiroFilterFactoryBean shiroFilterFactoryBean=new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        //注册拦截方案
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("token", new JwtShiroFilter());
        shiroFilterFactoryBean.setFilters(filterMap);
        //定义拦截规则
        Map<String, String> filterRuleMap = new HashMap<>();
        //登陆相关api不需要被过滤器拦截
        filterRuleMap.put("/api/wx/user/login/**", "anon");
        filterRuleMap.put("/api/response/**", "anon");
        // 所有请求通过JWT Filter
        filterRuleMap.put("/**", "token");
        return shiroFilterFactoryBean;
    }

    /**
     * 因为本项目只用了一个Realm，所以使用了构造器进行初始化，该构造器只适合单Realm的情况
     * @param tokenRealm
     * @return
     */
    @Bean
    public DefaultWebSecurityManager securityManager(TokenRealm tokenRealm){
        DefaultWebSecurityManager defaultWebSecurityManager=new DefaultWebSecurityManager(tokenRealm);
        //设置realm
        defaultWebSecurityManager.setRealm(tokenRealm);
        //关闭session
        DefaultSubjectDAO subjectDAO = (DefaultSubjectDAO) defaultWebSecurityManager.getSubjectDAO();
        DefaultSessionStorageEvaluator evaluator = (DefaultSessionStorageEvaluator) subjectDAO.getSessionStorageEvaluator();
        evaluator.setSessionStorageEnabled(Boolean.FALSE);
        subjectDAO.setSessionStorageEvaluator(evaluator);
        return defaultWebSecurityManager;
    }

/**
 * ============================= Shiro注解设置  ===============================================
 */
    /**
     *  开启Shiro的注解(如@RequiresRoles,@RequiresPermissions),需借助SpringAOP扫描使用Shiro注解的类,并在必要时进行安全逻辑验证
     * 配置以下两个bean(DefaultAdvisorAutoProxyCreator和AuthorizationAttributeSourceAdvisor)即可实现此功能
     * @return
     */
    @Bean
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    /**
     * 开启aop注解支持
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}

````

## 二、登录配置

我们希望用户在访问登录时获得一个token，微信使用的是code，我们没必要去检查密码，若不是微信小程序，可以使用密码判断

### 1.编写controller，调用loginService

比较简单不多赘述

### 2.编写loginService

我们计划使用spring提供的http工具，需要进行配置，在下个部份讲解

````java
@Service
public class LoginServiceImpl implements LoginService {
    @Value("${app.id}")
    private String appid;
    @Value("${app.secret}")
    private String appSecret;
    @Autowired
    RestTemplate restTemplate;
    @Autowired
    UserDao userDao;
    @Autowired
    JwtUtil jwtUtil;

    /**
     * @param code
     * @return
     */
    @Override
    public String login(String code) {
        String resultJson = analysisInfo(code);
        WxLoginResponseVo wxResponse = JSONObject.toJavaObject(JSONObject.parseObject(resultJson), WxLoginResponseVo.class);
        if (!wxResponse.getErrcode().equals("0")) {
            throw new WxApiException("请求微信api失败 : " + wxResponse.getErrmsg());
        } else {
            //3 . 先从本地数据库中查找用户是否存在
            User userInfo = userDao.findByWxOpenid(wxResponse.getOpenid());
            String sessionKey = wxResponse.getSession_key();
            //不存在就新建用户
            if (userInfo == null) {
                userInfo = new User(wxResponse.getOpenid(), "佚名", "0000-00-00", "未知", sessionKey);
                userDao.newUser(userInfo);
            } else {
                //4 . 更新sessionKey和 登陆时间
                userInfo.setSessionKey(sessionKey);
                userDao.fixSessionKeyById(userInfo);
            }
            //5 . JWT 返回自定义登陆态 Token
            String token = jwtUtil.createTokenByWxAccount(userInfo);
            return token;
        }

    }

    /**
     * 使用code获得微信api的用户json信息
     *
     * @param code
     * @return
     */
    private String analysisInfo(String code) {
        String code2SessionUrl = WxApiEnum.LOGIN_URL.getString();
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("appid", appid);
        params.add("secret", appSecret);
        params.add("js_code", code);
        params.add("grant_type", "authorization_code");
        URI code2Session = getURIwithParams(code2SessionUrl, params);
        return restTemplate.exchange(code2Session, HttpMethod.GET, new HttpEntity<String>(new HttpHeaders()), String.class).getBody();
    }

    /**
     * URI工具类
     *
     * @param url    url
     * @param params 参数
     * @return URI
     */
    private URI getURIwithParams(String url, MultiValueMap<String, String> params) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url).queryParams(params);
        return builder.build().encode().toUri();
    }
}

````

### 3.编写SpringHttp工具类RestTemplate

```java
@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate(ClientHttpRequestFactory factory) {
        return new RestTemplate(factory);
    }

    @Bean
    public ClientHttpRequestFactory simpleClientHttpRequestFactory() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setReadTimeout(1000 * 60);
        //读取超时时间为单位为60秒
        factory.setConnectTimeout(1000 * 10);
        //连接超时时间设置为10秒
        return factory;
    }
}
```

### 4.使用RestTemplate时，需要我们设定一个结果类进行映射，我们实现一个

```java
@Data
public class WxLoginResponseVo {
    private String openid;
    private String session_key;
    private String unionid;
    private String errcode = "0";
    private String errmsg;
    private int expires_in;
}
```
