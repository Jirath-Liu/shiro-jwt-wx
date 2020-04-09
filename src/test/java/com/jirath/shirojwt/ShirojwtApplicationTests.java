package com.jirath.shirojwt;

import com.jirath.shirojwt.util.enums.WxApiEnum;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class ShirojwtApplicationTests {
private  final Logger logger = LoggerFactory.getLogger(getClass());
    @Test
    void contextLoads() {
    }

    @Value("${jwt.secret}")
    String secret;
    @Test
    void getValue(){
        System.out.println(secret);
    }

    @Test
    void testEnum(){
        System.out.println(WxApiEnum.LOGIN_URL.getString());
    }

}
