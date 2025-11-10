// --- 1. Importações ---
const express = require('express');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs'); 
const path = require('path');
const cors = require('cors'); 
const mime = require('mime-types'); 

// --- 2. Configuração Inicial ---
dotenv.config(); 

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const NAS_ROOT_PATH = process.env.NAS_ROOT_PATH; 
const ADMIN_API_KEY = process.env.ADMIN_API_KEY; 

// Logs de inicialização
console.log(`🔑 Chave JWT usada: ${JWT_SECRET ? JWT_SECRET.substring(0, 4) + '...' : 'NÃO DEFINIDA!'}`);
console.log(`🔑 Chave Admin usada: ${ADMIN_API_KEY ? ADMIN_API_KEY.substring(0, 4) + '...' : 'NÃO DEFINIDA!'}`);
console.log(`🌐 Caminho Raiz do NAS: ${NAS_ROOT_PATH || 'NÃO DEFINIDO!'}`);

// --- 3. Middlewares ---
app.use(cors()); 
app.use(express.json()); 

// --- 4. Configuração do Pool do PostgreSQL ---
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    connectionTimeoutMillis: 5000, 
    statement_timeout: 10000, 
});

// Teste de conexão inicial
pool.connect()
    .then(() => console.log('✅ Conexão bem-sucedida com o PostgreSQL!'))
    .catch(err => console.error('❌ ERRO DE CONEXÃO COM O POSTGRES:', err.stack));

// --- 5. Middleware de Log Universal ---
app.use((req, res, next) => {
    console.log(`[REQUEST RECEIVED] Method: ${req.method}, Path: ${req.url}`);
    next();
});

// --- 6. Middlewares de Autenticação ---

// Middleware para verificar o Token JWT (para Representantes)
const verifyToken = (req, res, next) => {
    console.log('[AUTH CHECK] Iniciando verificação de token.');
    let token = req.headers['authorization']; 
    let tokenSource = 'Header';

    if (!token && req.query.token) {
        token = req.query.token;
        tokenSource = 'Query URL';
    }

    if (!token) {
        console.warn('[AUTH CHECK] Token ausente. Retornando 401.');
        return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });
    }

    if (token.startsWith('Bearer ')) {
        token = token.slice(7, token.length);
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; 
        console.log(`[AUTH CHECK] Token válido (Fonte: ${tokenSource}). Usuário: ${req.user.usuario}. Prosseguindo.`);
        next();
    } catch (error) {
        console.error('[AUTH CHECK] Falha na verificação do Token:', error.message);
        return res.status(403).json({ error: 'Token inválido ou expirado.' });
    }
};

// Middleware para verificar a Chave de Admin (para Resetar Senhas)
const verifyAdminKey = (req, res, next) => {
    const adminKey = req.headers['x-admin-key'];
    if (!adminKey || adminKey !== ADMIN_API_KEY) {
        console.warn('[ADMIN AUTH] Falha na autenticação de admin. Chave inválida ou ausente.');
        return res.status(403).json({ error: 'Acesso de administrador não autorizado.' });
    }
    console.log('[ADMIN AUTH] Acesso de administrador verificado.');
    next();
};


// --- 7. Rotas Públicas (Login/Cadastro) ---

app.get('/api/health', (req, res) => {
    console.log('[HEALTH CHECK] Servidor OK.');
    res.json({ status: "ok", message: "API is running" });
});

// Rota de Cadastro (Use via Postman)
app.post('/api/register', async (req, res) => {
    console.log('[REGISTER - BODY RECEIVED] Conteúdo do corpo:', req.body);
    const { usuario, senha, nome_completo } = req.body;
    const saltRounds = 10;

    if (!usuario || !senha) {
        console.warn('[REGISTER - VALIDAÇÃO FALHOU] Usuário ou senha ausentes.');
        return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
    }

    try {
        console.log(`[REGISTER - BD QUERY] Inserindo usuário: ${usuario}`);
        const senhaHash = await bcrypt.hash(senha, saltRounds);
        
        const result = await pool.query(
            'INSERT INTO usuarios (usuario, senha_hash, nome_completo) VALUES ($1, $2, $3) RETURNING id',
            [usuario, senhaHash, nome_completo]
        );
        
        res.status(201).json({ message: 'Usuário criado com sucesso!', userId: result.rows[0].id });
    
    } catch (err) {
        if (err.code === '23505') {
            console.warn(`[REGISTER - CONFLITO] Usuário '${usuario}' já existe.`);
            return res.status(409).json({ error: 'Nome de usuário já existe.' });
        }
        console.error('[REGISTER - ERRO CRÍTICO]', err);
        res.status(500).json({ error: 'Erro interno ao criar usuário.' });
    }
});

// Rota de Login
app.post('/api/login', async (req, res) => {
    console.log('[LOGIN - BODY RECEIVED] Conteúdo do corpo:', req.body);
    const { usuario, senha } = req.body;

    if (!usuario || !senha) {
        console.warn('[LOGIN - VALIDAÇÃO FALHOU] Usuário ou senha ausentes.');
        return res.status(400).json({ error: 'Usuário e senha são obrigatórios.' });
    }

    try {
        console.log(`[LOGIN - BD QUERY] Executando busca para: ${usuario}`);
        const userResult = await pool.query(
            'SELECT * FROM usuarios WHERE usuario = $1',
            [usuario]
        );

        if (userResult.rows.length === 0) {
            console.warn(`[LOGIN - FALHA] Usuário '${usuario}' não encontrado.`);
            return res.status(401).json({ error: 'Credenciais inválidas.' });
        }

        const user = userResult.rows[0];

        const match = await bcrypt.compare(senha, user.senha_hash);

        if (!match) {
            console.warn(`[LOGIN - FALHA] Senha incorreta para '${usuario}'.`);
            return res.status(401).json({ error: 'Credenciais inválidas.' });
        }

        const token = jwt.sign(
            { id: user.id, usuario: user.usuario },
            JWT_SECRET,
            { expiresIn: '1d' } 
        );

        console.log(`[LOGIN - SUCESSO] Token gerado para '${usuario}'.`);
        res.json({
            message: `Bem-vindo, ${user.nome_completo || user.usuario}!`,
            token: token
        });

    } catch (err) {
        console.error('Erro no login:', err);
        res.status(500).json({ error: 'Erro interno ao tentar fazer login.' });
    }
});

// --- 8. Rotas Protegidas (Catálogo e Gerenciamento de Senha) ---

// NOVO: Rota para buscar TODOS os códigos de peças (para autocomplete)
app.get('/api/catalog/all', verifyToken, async (req, res) => {
    console.log('[CATALOG ALL] Recebida requisição para listar todos os códigos.');
    try {
        const result = await pool.query('SELECT cod_peca FROM catalogo_pecas ORDER BY cod_peca ASC');
        
        // Mapeia o resultado para um array simples de strings
        const codes = result.rows.map(row => row.cod_peca);
        
        console.log(`[CATALOG ALL] Sucesso. ${codes.length} códigos encontrados.`);
        res.json(codes);

    } catch (error) {
        console.error('[CATALOG ALL - ERRO CRÍTICO]', error);
        res.status(500).json({ error: 'Erro interno ao buscar lista de peças.' });
    }
});


// Rota para BUSCAR a lista de fotos de uma peça
app.get('/api/search', verifyToken, async (req, res) => {
    const { cod_peca } = req.query; 
    console.log(`[SEARCH - ENTRADA DE DADOS] Query recebida. Peça: ${cod_peca}`);

    if (!cod_peca) {
        return res.status(400).json({ error: 'O código da peça (cod_peca) é obrigatório na query URL.' });
    }

    try {
        console.log(`[SEARCH - BD START] Iniciando pool.query para peça: ${cod_peca}`);
        
        const result = await pool.query(
            'SELECT caminho_nas FROM catalogo_pecas WHERE cod_peca = $1',
            [cod_peca]
        );
        
        if (result.rows.length === 0) {
            console.warn(`[SEARCH - 404] Peça '${cod_peca}' não encontrada no BD.`);
            return res.status(404).json({ error: 'Código de peça não encontrado no catálogo.' });
        }

        const caminho_nas = result.rows[0].caminho_nas;
        console.log(`[SEARCH - BD CONCLUÍDO] Caminho retornado: ${caminho_nas}`);
        
        const absolutePath = caminho_nas; 

        console.log(`[SEARCH - FS READ] Tentando ler pasta em: ${absolutePath}`);
        const files = await fs.promises.readdir(absolutePath);

        const imageFiles = files
            .filter(file => {
                const mimeType = mime.lookup(file); 
                return mimeType && mimeType.startsWith('image/');
            })
            .map(file => ({
                filename: file,
                url: `/api/photo/${cod_peca}/${file}` 
            }));

        console.log(`[SEARCH - SUCESSO] Encontradas ${imageFiles.length} fotos para ${cod_peca}.`);
        return res.json({ 
            cod_peca, 
            fotos: imageFiles 
        });

    } catch (error) {
        console.error(`[SEARCH - ERRO CRÍTICO] Erro ao buscar ou ler a pasta da peça ${cod_peca}:`, error);
        res.status(500).json({ error: 'Erro interno ao acessar o catálogo de arquivos.', details: error.code });
    }
});

// Rota para SERVIR (Streaming) o arquivo de foto
app.get('/api/photo/:codPeca/:filename', verifyToken, async (req, res) => {
    const { codPeca, filename } = req.params;
    let absolutePath = ''; 
    let fileStream;

    try {
        console.log(`[PHOTO STREAM - BD START] Buscando caminho para ${codPeca}`);
        const result = await pool.query(
            'SELECT caminho_nas FROM catalogo_pecas WHERE cod_peca = $1',
            [codPeca]
        );

        if (result.rows.length === 0) {
            console.error(`[PHOTO STREAM - 404] Peça ${codPeca} não encontrada no BD.`);
            return res.status(404).json({ error: 'Peça não encontrada no catálogo.' });
        }

        const caminho_nas = result.rows[0].caminho_nas;

        absolutePath = path.join(caminho_nas, filename);
        
        console.log(`[PHOTO STREAM - FS READ] Tentando STREAM do arquivo em: ${absolutePath}`);

        res.setHeader('Content-Type', mime.lookup(filename) || 'image/jpeg'); 
        
        fileStream = fs.createReadStream(absolutePath);

        fileStream.on('error', (err) => {
            console.error('[ERRO FATAL NO STREAM DE FOTO (Permissão ou Caminho)]: ', err);
            if (res.headersSent) return;
            res.status(500).json({ 
                error: 'Erro ao ler o arquivo da peça.', 
                details: err.code,
                path_tried: absolutePath 
            });
        });

        fileStream.pipe(res);

    } catch (error) {
        console.error('[ERRO INTERNO NA ROTA /api/photo]:', error);
        if (res.headersSent) return;
        res.status(500).json({ error: 'Erro interno do servidor ao acessar a foto.' });
    }
});

// Rota para o USUÁRIO (Representante) mudar a própria senha
app.post('/api/change-password', verifyToken, async (req, res) => {
    const { senhaAntiga, novaSenha } = req.body;
    const userId = req.user.id; 
    const usuario = req.user.usuario;

    console.log(`[CHANGE PWD] Usuário '${usuario}' (ID: ${userId}) tentando mudar a senha.`);

    if (!senhaAntiga || !novaSenha) {
        return res.status(400).json({ error: 'Senha antiga e nova senha são obrigatórias.' });
    }

    try {
        const userResult = await pool.query('SELECT senha_hash FROM usuarios WHERE id = $1', [userId]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        const user = userResult.rows[0];

        const match = await bcrypt.compare(senhaAntiga, user.senha_hash);
        if (!match) {
            console.warn(`[CHANGE PWD] Falha: Senha antiga incorreta para '${usuario}'.`);
            return res.status(401).json({ error: 'Senha antiga incorreta.' });
        }

        const saltRounds = 10;
        const novaSenhaHash = await bcrypt.hash(novaSenha, saltRounds);

        await pool.query('UPDATE usuarios SET senha_hash = $1 WHERE id = $2', [novaSenhaHash, userId]);

        console.log(`[CHANGE PWD] Sucesso: Senha de '${usuario}' alterada.`);
        res.json({ message: 'Senha alterada com sucesso!' });

    } catch (error) {
        console.error(`[CHANGE PWD] Erro ao alterar senha para '${usuario}':`, error);
        res.status(500).json({ error: 'Erro interno ao alterar a senha.' });
    }
});

// Rota para o ADMINISTRADOR resetar a senha de um usuário
app.post('/api/admin/reset-password', verifyAdminKey, async (req, res) => {
    const { usuario, novaSenha } = req.body; 

    console.log(`[ADMIN RESET PWD] Tentativa de resetar senha para '${usuario}'.`);

    if (!usuario || !novaSenha) {
        return res.status(400).json({ error: 'Usuário-alvo e nova senha são obrigatórios.' });
    }

    try {
        const saltRounds = 10;
        const novaSenhaHash = await bcrypt.hash(novaSenha, saltRounds);

        const result = await pool.query(
            'UPDATE usuarios SET senha_hash = $1 WHERE usuario = $2',
            [novaSenhaHash, usuario]
        );

        if (result.rowCount === 0) {
            console.warn(`[ADMIN RESET PWD] Falha: Usuário '${usuario}' não encontrado.`);
            return res.status(404).json({ error: `Usuário '${usuario}' não encontrado.` });
        }

        console.log(`[ADMIN RESET PWD] Sucesso: Senha de '${usuario}' resetada.`);
        res.json({ message: `Senha para '${usuario}' resetada com sucesso.` });

    } catch (error) {
        console.error(`[ADMIN RESET PWD] Erro ao resetar senha para '${usuario}':`, error);
        res.status(500).json({ error: 'Erro interno ao resetar a senha.' });
    }
});


// --- 9. Inicialização do Servidor ---
app.listen(port, () => {
    console.log(`🚀 Servidor rodando em http://localhost:${port}`);
});