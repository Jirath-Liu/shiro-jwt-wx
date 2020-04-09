package com.jirath.shirojwt;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author Jirath
 */
@MapperScan("com.jirath.shirojwt.dao")
@SpringBootApplication
public class ShirojwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(ShirojwtApplication.class, args);
    }

}
