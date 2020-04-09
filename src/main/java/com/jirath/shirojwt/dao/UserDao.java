package com.jirath.shirojwt.dao;

import com.jirath.shirojwt.pojo.User;
import org.springframework.stereotype.Repository;

/**
 * @// TODO: 2020/4/9  dao层未实现
 * @author Jirath
 * @date 2020/4/6
 * @description: dao层未实现
 */
@Repository
public interface UserDao {
    /**
     * 根据wxid找信息
     * @param wxId
     * @return
     */
    User findByWxOpenid(String wxId);

    /**
     * 新用户，拥有全部信息
     * @param user
     */
    void newUser(User user);

    /**
     * 根据userId修改sessionKey
     * @param user
     */
    void fixSessionKeyById(User user);
}
