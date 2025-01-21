package com.generation.blogpessoal.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override // Método de Filtro da Autenticação do JWT
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;
    
        try{
            if (authHeader != null && authHeader.startsWith("Bearer ")) { // Verifica se existe algum dado no Cabeçalho da Requisição chamado Authorization
                token = authHeader.substring(7); // Tira a palavra Bearer e pega apenas as informações criptografadas
                username = jwtService.extractUsername(token); // Extrai do Token o email descriptografado
            }

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {  // Verifica se existe um email no token e se o mesmo não está gravado na Secuirty Context
                UserDetails userDetails = userDetailsService.loadUserByUsername(username); // Chama o método para buscar o usuário no BD e trazer os dados em um formato que a Security entenda
                    
                if (jwtService.validateToken(token, userDetails)) { // Faz a validação do Token, comparando o email de dentro do token com o email recuperado pelo método acima
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken); // Essas 3 linhas, gravam o usuário encontrado dentro da Security Context, para futuros acessos
                }
            
            }
            filterChain.doFilter(request, response); // Se não houve nenhuma Exceção, retorna o Fluxo de execução para a Basic Security Config

        }catch(ExpiredJwtException | UnsupportedJwtException | MalformedJwtException 
                | SignatureException | ResponseStatusException e){
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }
    }
}