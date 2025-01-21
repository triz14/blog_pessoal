package com.generation.blogpessoal.security;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

//A Classe JwtService é responsável por criar e validar o Token JWT
@Component
public class JwtService {

	public static final String SECRET = "8ht7g47gm7ElSP1NzvMeztpKVt7UVxmrILQ2lXdZ13O70tRMAgcZrC6rk7b1iRwc";
	
	// Codifica a SECRET e gera a Assinatura do Token JWT
	private Key getSignKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	// Retorna todas as claims(Informações), inseridas no Payload(Corpo) do Token JWT.
	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(getSignKey()).build()
				.parseClaimsJws(token).getBody();
	}
	
	// Método Genérico que serve para retornar uma Claim(Informação) em espefico
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	
	// Retorna os dados da Claim sub, onde se encontra o usuario(e-mail)
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	// Retorna os dados da Claim exp, onde se encontra a data e o horário de expiração do Token JWT
	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}
	
	// Método que verifica se o Token está ou não expirado
	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}
	
	// Método que verifica se o Token pertence ao MESMO usuário que enviou o token
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	
	// Método que cria um Token válido para o usuário
	private String createToken(Map<String, Object> claims, String userName) {
		return Jwts.builder()
					.setClaims(claims)
					.setSubject(userName)
					.setIssuedAt(new Date(System.currentTimeMillis()))
					.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
					.signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
	}
	
	// Método responsavel por criar um novo TOKEN sempre que o anterior expirar ou o usuário logar
	public String generateToken(String userName) {
		Map<String, Object> claims = new HashMap<>();
		return createToken(claims, userName);
	}

}