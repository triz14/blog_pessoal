package com.generation.blogpessoal.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.generation.blogpessoal.model.UsuarioLogin;
import com.generation.blogpessoal.model.Usuario;
import com.generation.blogpessoal.repository.UsuarioRepository;
import com.generation.blogpessoal.security.JwtService;

// possui as regras de negócio (usada para tirar a complexidade da controller)
@Service
public class UsuarioService {

	@Autowired
	private UsuarioRepository usuarioRepository;

	@Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;
    
    // Método responsavel por Cadastrar um novo Usuário
	public Optional<Usuario> cadastrarUsuario(Usuario usuario) {

		if (usuarioRepository.findByUsuario(usuario.getUsuario()).isPresent())
			return Optional.empty();

		usuario.setSenha(criptografarSenha(usuario.getSenha())); // criptografa a senha antes de salvar no banco

		return Optional.of(usuarioRepository.save(usuario));
	
	}
	
	// Método responsavel por Atualizar um Usuário
	public Optional<Usuario> atualizarUsuario(Usuario usuario) {
		
		if(usuarioRepository.findById(usuario.getId()).isPresent()) { // Verifica se existe um ID dentro do objeto de validação

			Optional<Usuario> buscaUsuario = usuarioRepository.findByUsuario(usuario.getUsuario()); // Busca o Usuário no BD

			if ( (buscaUsuario.isPresent()) && ( buscaUsuario.get().getId() != usuario.getId())) // Se os IDs do usuário do BD e da requisição não são iguais, emite uma Exceção
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Usuário já existe!", null); 

			usuario.setSenha(criptografarSenha(usuario.getSenha())); // Criptografa a nova senha

			return Optional.ofNullable(usuarioRepository.save(usuario)); // Salve no banco
			
		}

		return Optional.empty();
	
	}	
	
	// Método responsavel por fazer a autenticação(Login) do Usuário
	public Optional<UsuarioLogin> autenticarUsuario(Optional<UsuarioLogin> usuarioLogin) {
        
		// Pega os dados do usuário que foi enviado na requisição(email/senha) e gera um Objeto que a Security consiga entender - Vide o UserDetailsImpl
		var credenciais = new UsernamePasswordAuthenticationToken(usuarioLogin.get().getUsuario(), usuarioLogin.get().getSenha());
		
		// Aqui é feito pelo Spring a autenticação do usuário, isto é, é feita a descriptografia e comparação das senhas com os dados do banco
		Authentication authentication = authenticationManager.authenticate(credenciais);
        
		// Executa se a autenticação foi efetuada com sucesso
		if (authentication.isAuthenticated()) {

			// Busca os dados do usuário
			Optional<Usuario> usuario = usuarioRepository.findByUsuario(usuarioLogin.get().getUsuario());

			// Se o usuário foi encontrado
			if (usuario.isPresent()) {

				// Preenche o Objeto usuarioLogin com os dados encontrados
				usuarioLogin.get().setId(usuario.get().getId());
                usuarioLogin.get().setNome(usuario.get().getNome());
                usuarioLogin.get().setFoto(usuario.get().getFoto());
                usuarioLogin.get().setToken(gerarToken(usuarioLogin.get().getUsuario())); // Chama o método para montar o Token, usando o email do usuário
                usuarioLogin.get().setSenha("");
				
                 // Retorna o Objeto preenchido
			   return usuarioLogin;
			
			}

        } 
            
		return Optional.empty();

    }
	
	// Método que vai criptografar a nossa senha
	private String criptografarSenha(String senha) {

		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		
		return encoder.encode(senha);

	}
	
	// Método que vai gerar o Token a partir do usuário
	private String gerarToken(String usuario) {
		return "Bearer " + jwtService.generateToken(usuario);
	}

}