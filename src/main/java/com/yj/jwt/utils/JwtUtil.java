package com.yj.jwt.utils;

import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.yj.jwt.entity.BusinessException;
import com.yj.jwt.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

	private final static Logger logger = LoggerFactory.getLogger(JwtUtil.class);

	private static String jwtKey;

	@Value("${jwtKey}")
	public void setJwtKey(String jwtKey) {
		JwtUtil.jwtKey = jwtKey;
	}

	/**
	 * 由字符串生成加密key
	 * 
	 * @return
	 */
	public static SecretKey generalKey() {
		byte[] encodedKey = Base64.decodeBase64(jwtKey);
		SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
		return key;
	}

	/**
	 * 创建jwt
	 * 
	 * @param id
	 * @param subject
	 * @param ttlMillis
	 * @return
	 * @throws Exception
	 */
	public static String createJWT(String id, String subject, long ttlMillis) throws BusinessException {
		JwtBuilder builder;
		try {
			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
			long nowMillis = System.currentTimeMillis();
			Date now = new Date(nowMillis);
			logger.info("当前时间是：" + now);
			SecretKey key = generalKey();
			builder = Jwts.builder().setId(id).setIssuedAt(now).setSubject(subject).signWith(signatureAlgorithm, key);
			if (ttlMillis >= 0) {
				long expMillis = nowMillis + ttlMillis;
				Date exp = new Date(expMillis);
				logger.info("失效时间是：" + exp);
				builder.setExpiration(exp);
			}
		} catch (Exception e) {
			throw new BusinessException("生成jwt时发生异常");
		}
		return builder.compact();
	}

	/**
	 * 解密jwt
	 * 
	 * @param jwt
	 * @return
	 * @throws Exception
	 */
	public static Claims parseJWT(String jwt) throws ExpiredJwtException {
		Claims claims = null;
		SecretKey key = generalKey();
		claims = Jwts.parser().setSigningKey(key).parseClaimsJws(jwt).getBody();
		return claims;
	}

	/**
	 * 生成subject信息
	 * 
	 * @param user
	 * @return
	 */
	public static String generalSubject(User user) {
		JSONObject jo = new JSONObject();
		jo.put("name", user.getName());
		jo.put("id", user.getId());
		return jo.toJSONString();
	}

	/**
	 * 获取jwt内的User
	 * 
	 * @param jwt
	 * @return user
	 */
	public static User getJwtUser(String jwt) {
		String userStr = null;
		User user = null;
		try {
			SecretKey key = generalKey();
			userStr = Jwts.parser().setSigningKey(key).parseClaimsJws(jwt).getBody().getSubject();
			user = JSON.parseObject(userStr, User.class);
		} catch (Exception e) {
			e.printStackTrace();
			throw new BusinessException("获取jwt内的user对象时发生异常");
		}
		return user;
	}
}
