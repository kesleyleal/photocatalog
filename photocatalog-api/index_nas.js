// --- 1. Importações ---
const { Pool } = require('pg');
const dotenv = require('dotenv');
const fs = require('fs').promises; // Usando File System (promises)
const path = require('path');

// --- 2. Configuração ---
dotenv.config(); // Carrega o .env

const NAS_ROOT_PATH = process.env.NAS_ROOT_PATH;

if (!NAS_ROOT_PATH) {
    console.error("❌ ERRO FATAL: NAS_ROOT_PATH não está definido no .env.");
    console.error("Este script não pode ser executado sem o caminho raiz do NAS.");
    process.exit(1);
}

// Configuração do Pool do PostgreSQL
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// --- 3. Função Principal de Indexação ---
async function startIndexing() {
    console.log(`--- Iniciando indexação do NAS ---`);
    console.log(`Origem (NAS_ROOT_PATH): ${NAS_ROOT_PATH}\n`);
    
    let client;
    let indexedCount = 0;
    let errorCount = 0;

    try {
        // Conecta ao Banco de Dados
        client = await pool.connect();
        console.log("✅ Conexão com o PostgreSQL estabelecida.");

        // Lê o diretório raiz do NAS
        const items = await fs.readdir(NAS_ROOT_PATH);
        
        console.log(`🔎 Encontrados ${items.length} itens no diretório raiz. Verificando...`);

        // Processa cada item em paralelo
        const processingPromises = items.map(async (itemName) => {
            const itemPath = path.join(NAS_ROOT_PATH, itemName);
            
            try {
                // Verifica se o item é um diretório
                const stats = await fs.stat(itemPath);
                
                if (stats.isDirectory()) {
                    // Se for um diretório, este é o nosso cod_peca
                    const cod_peca = itemName;
                    const caminho_nas = itemPath; // Este é o caminho completo da pasta

                    // Insere ou Atualiza (UPSERT) no banco de dados
                    // Se o cod_peca já existe, atualiza o caminho_nas
                    const query = `
                        INSERT INTO catalogo_pecas (cod_peca, caminho_nas)
                        VALUES ($1, $2)
                        ON CONFLICT (cod_peca) 
                        DO UPDATE SET 
                            caminho_nas = EXCLUDED.caminho_nas,
                            data_indexacao = CURRENT_TIMESTAMP;
                    `;
                    
                    await client.query(query, [cod_peca, caminho_nas]);
                    console.log(`  -> OK: [${cod_peca}]`);
                    indexedCount++;
                }
            } catch (fsErr) {
                console.warn(`  -> AVISO: Falha ao ler o item '${itemName}'. Erro: ${fsErr.message}`);
                errorCount++;
            }
        });

        // Espera todas as pastas serem processadas
        await Promise.all(processingPromises);

    } catch (err) {
        console.error("\n❌ ERRO CRÍTICO DURANTE A INDEXAÇÃO:", err);
    } finally {
        if (client) {
            client.release();
        }
        pool.end();
        console.log("\n--- Indexação Concluída ---");
        console.log(`✅ Pastas indexadas/atualizadas: ${indexedCount}`);
        console.log(`⚠️ Itens ignorados/com erro: ${errorCount}`);
    }
}

// --- 4. Executar o Script ---
startIndexing();